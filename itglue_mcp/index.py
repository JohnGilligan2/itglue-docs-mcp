"""The local mirror of IT Glue.

Not a cache in the "nice to have" sense — a prerequisite. IT Glue's filters are
exact-match only (see search.py), so substring/fuzzy lookup has to run over a
local copy.

Sizing, measured against the live tenant:

    organizations       95        configurations      733
    contacts           318        locations           215
    passwords        5,117        flexible assets     380
    domains             11        expirations          29
    documents          300        (244 with text, 56 binary uploads)

  core mirror : ~7k rows in ~10 requests   (seconds)
  doc mirror  : ~400 requests              (minutes — 95 listings + 300 fetches)
  all prose   : ~182k chars of documents + ~89k of config notes

against a documented ceiling of 3,000 requests per 5 minutes. A full cold
rebuild fits comfortably in one window. Everything is held in RAM: the whole
corpus is small, so there is no volume to mount and a restart just re-syncs.

Redaction happens HERE, on the way in, so nothing downstream can leak a field
by forgetting to strip it. Password records are scrubbed before they are ever
stored.
"""
from __future__ import annotations

import html
import logging
import re
import threading
import time
from typing import Dict, List, Optional

from .client import ItGlueClient
from .config import IndexConfig, SafetyConfig, ItGlueConfig
from .redact import attrs, is_visible, itglue_link, scrub_password_record

logger = logging.getLogger("itglue_mcp.index")

_TAG = re.compile(r"<[^>]+>")
_BR = re.compile(r"<br\s*/?>", re.I)
_BLOCK_END = re.compile(r"</(p|div|li|tr|h[1-6]|table)>", re.I)
_LI = re.compile(r"<li[^>]*>", re.I)
_BLANKS = re.compile(r"\n{3,}")


def html_to_text(raw: Optional[str]) -> str:
    """IT Glue document sections are HTML (often Google-Docs paste soup).

    Convert to readable plain text: preserve line structure, drop tags, unescape
    entities, and normalise the non-breaking spaces that litter this corpus.
    """
    if not raw:
        return ""
    s = _BR.sub("\n", raw)
    s = _BLOCK_END.sub("\n", s)
    s = _LI.sub("\n - ", s)
    s = _TAG.sub("", s)
    s = html.unescape(s)
    s = s.replace("\xa0", " ").replace("", "")
    s = "\n".join(line.rstrip() for line in s.splitlines())
    return _BLANKS.sub("\n\n", s).strip()


class ItGlueIndex:
    """Thread-safe in-memory mirror with independent TTLs for core and docs."""

    def __init__(
        self,
        client: ItGlueClient,
        idx_cfg: IndexConfig,
        safety: SafetyConfig,
        itglue_cfg: ItGlueConfig,
    ) -> None:
        self._client = client
        self._cfg = idx_cfg
        self._safety = safety
        self._sub = itglue_cfg.subdomain_url

        self._lock = threading.RLock()
        self._core_lock = threading.Lock()
        self._docs_lock = threading.Lock()

        self.organizations: List[dict] = []
        self.configurations: List[dict] = []
        self.contacts: List[dict] = []
        self.locations: List[dict] = []
        self.passwords: List[dict] = []
        self.domains: List[dict] = []
        self.expirations: List[dict] = []
        self.flexible_assets: List[dict] = []
        self.flexible_asset_types: List[dict] = []
        self.documents: List[dict] = []

        self._core_at: float = 0.0
        self._docs_at: float = 0.0
        self._docs_building = False
        self._docs_error: Optional[str] = None
        self._core_error: Optional[str] = None

    # ------------------------------------------------------------- lifecycle

    def start_background_warm(self) -> None:
        """Warm core synchronously-ish then docs in the background.

        Core is fast enough to block the first call; documents are not, so they
        get a thread. Tools that need documents report "still indexing" rather
        than hanging for minutes.
        """
        threading.Thread(target=self._warm_all, name="itglue-warm", daemon=True).start()

    def _warm_all(self) -> None:
        try:
            self.ensure_core()
        except Exception as exc:  # noqa: BLE001 — never kill the thread
            logger.error("core warm failed: %s", exc)
        if self._cfg.warm_docs_on_start:
            try:
                self.ensure_docs()
            except Exception as exc:  # noqa: BLE001
                logger.error("docs warm failed: %s", exc)

    # ----------------------------------------------------------------- core

    def ensure_core(self, force: bool = False) -> None:
        with self._core_lock:
            fresh = (time.time() - self._core_at) < self._cfg.core_ttl_seconds
            if fresh and not force and self.organizations:
                return
            logger.info("building core mirror")
            t0 = time.time()
            try:
                orgs = [attrs(r) for r in self._client.organizations()]
                configs = [attrs(r) for r in self._client.configurations()]
                contacts = [attrs(r) for r in self._client.contacts()]
                locations = [attrs(r) for r in self._client.locations()]
                # Scrubbed on the way IN — see module docstring.
                passwords = [
                    scrub_password_record(r, self._safety.include_password_username)
                    for r in self._client.passwords()
                ]
                domains = [attrs(r) for r in self._client.domains()]
                expirations = [attrs(r) for r in self._client.expirations()]

                fa_types = [attrs(r) for r in self._client.flexible_asset_types()]
                flex: List[dict] = []
                for t in fa_types:
                    for r in self._client.flexible_assets(t["id"]):
                        a = attrs(r)
                        a["flexible_asset_type_name"] = t.get("name")
                        a["flexible_asset_type_id"] = t["id"]
                        flex.append(a)
            except Exception as exc:  # noqa: BLE001
                self._core_error = str(exc)
                raise

            with self._lock:
                self.organizations = orgs
                self.configurations = configs
                self.contacts = contacts
                self.locations = locations
                self.passwords = passwords
                self.domains = domains
                self.expirations = expirations
                self.flexible_asset_types = fa_types
                self.flexible_assets = flex
                self._core_at = time.time()
                self._core_error = None
            logger.info(
                "core mirror built in %.1fs: %d orgs, %d configs, %d passwords, "
                "%d contacts, %d locations, %d flex assets",
                time.time() - t0, len(orgs), len(configs), len(passwords),
                len(contacts), len(locations), len(flex),
            )

    # ----------------------------------------------------------------- docs

    def ensure_docs(self, force: bool = False) -> None:
        """Build the document text index. ~400 requests; minutes, not seconds."""
        with self._docs_lock:
            fresh = (time.time() - self._docs_at) < self._cfg.docs_ttl_seconds
            if fresh and not force and self.documents:
                return
            self.ensure_core()
            logger.info("building document index (this takes a few minutes)")
            self._docs_building = True
            t0 = time.time()
            docs: List[dict] = []
            try:
                for org in list(self.organizations):
                    oid = org["id"]
                    try:
                        listing = self._client.organization_documents(oid)
                    except Exception as exc:  # noqa: BLE001 — one org must not kill the build
                        logger.warning("doc listing failed for org %s: %s", oid, exc)
                        continue
                    for item in listing:
                        a = attrs(item)
                        if not is_visible(a, self._safety.honor_restricted,
                                          self._safety.include_archived):
                            continue
                        doc = {
                            "id": a["id"],
                            "name": a.get("name") or "(untitled)",
                            "organization_id": oid,
                            "organization_name": org.get("name"),
                            "updated_at": a.get("updated_at"),
                            "is_uploaded": bool(a.get("is_uploaded")),
                            "document_folder_id": a.get("document_folder_id"),
                            "url": itglue_link(self._sub, oid, "docs", a["id"],
                                               a.get("resource_url")),
                            "text": "",
                        }
                        # Binary uploads have no sections; skip the fetch.
                        if not doc["is_uploaded"]:
                            try:
                                full = self._client.document(a["id"])
                                doc["text"] = self._sections_to_text(full)
                            except Exception as exc:  # noqa: BLE001
                                logger.warning("doc %s fetch failed: %s", a["id"], exc)
                        docs.append(doc)
            finally:
                self._docs_building = False

            with self._lock:
                self.documents = docs
                self._docs_at = time.time()
                self._docs_error = None
            with_text = sum(1 for d in docs if d["text"])
            logger.info(
                "document index built in %.0fs: %d docs, %d with text, %d chars",
                time.time() - t0, len(docs), with_text,
                sum(len(d["text"]) for d in docs),
            )

    @staticmethod
    def _sections_to_text(doc: dict) -> str:
        """Extract prose from a document record.

        Prefer `attributes.sections[].rendered-content`; fall back to the parallel
        `content[]` array's nested resource.content, which carries the same HTML
        in a different shape.
        """
        a = doc.get("attributes") or {}
        parts: List[str] = []
        for sec in a.get("sections") or []:
            sa = sec.get("attributes") or {}
            raw = sa.get("rendered-content") or sa.get("content") or ""
            txt = html_to_text(raw)
            if txt:
                parts.append(txt)
        if not parts:
            content = a.get("content")
            if isinstance(content, list):
                for sec in content:
                    res = sec.get("resource") if isinstance(sec, dict) else None
                    raw = (res or {}).get("content") if isinstance(res, dict) else None
                    txt = html_to_text(raw)
                    if txt:
                        parts.append(txt)
        return "\n\n".join(parts).strip()

    # --------------------------------------------------------------- status

    def status(self) -> Dict[str, object]:
        with self._lock:
            return {
                "core_built_at": (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._core_at))
                    if self._core_at else None
                ),
                "core_age_seconds": int(time.time() - self._core_at) if self._core_at else None,
                "core_error": self._core_error,
                "docs_built_at": (
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._docs_at))
                    if self._docs_at else None
                ),
                "docs_indexing_now": self._docs_building,
                "docs_error": self._docs_error,
                "counts": {
                    "organizations": len(self.organizations),
                    "configurations": len(self.configurations),
                    "contacts": len(self.contacts),
                    "locations": len(self.locations),
                    "passwords": len(self.passwords),
                    "flexible_assets": len(self.flexible_assets),
                    "domains": len(self.domains),
                    "expirations": len(self.expirations),
                    "documents": len(self.documents),
                    "documents_with_text": sum(1 for d in self.documents if d.get("text")),
                },
            }

    @property
    def docs_ready(self) -> bool:
        return bool(self.documents)

    @property
    def docs_indexing(self) -> bool:
        return self._docs_building

    # ------------------------------------------------------------- accessors

    def visible(self, records: List[dict]) -> List[dict]:
        return [
            r for r in records
            if is_visible(r, self._safety.honor_restricted, self._safety.include_archived)
        ]

    def org_by_id(self, org_id: str) -> Optional[dict]:
        return next((o for o in self.organizations if o["id"] == str(org_id)), None)

    def link(self, org_id: Optional[str], kind: str, rec: dict) -> str:
        return itglue_link(self._sub, org_id, kind, rec.get("id", ""), rec.get("resource_url"))
