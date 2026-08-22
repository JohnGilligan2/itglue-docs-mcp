"""IT Glue REST client. GET-ONLY, BY CONSTRUCTION.

Read this before changing anything in here.

The API key this server runs with has full write and delete rights against the
live tenant. That was verified, not assumed:

    PATCH  /configurations/999999999  -> 404 "Record not found"
    PATCH  /organizations/999999999   -> 404 "Record not found"
    PATCH  /passwords/999999999       -> 404 "Record not found"
    DELETE /configurations/999999999  -> 404

A key lacking write permission fails with 401/403 *before* the record lookup.
Getting 404 means the lookup ran, i.e. the mutation was authorized and merely
had nothing to act on. IT Glue does not offer a read-scoped classic API key, so
there is no server-side permission to lean on.

Therefore the read-only guarantee lives entirely in this file:

  1. `get()` is the only request method. There is no post/patch/put/delete.
  2. It hardcodes ``method="GET"`` and re-asserts it before dispatch.
  3. Any query string containing ``show_password`` is refused outright, so no
     future caller can talk this class into asking for a credential value.

Do not add a mutating helper "just for a draft document". If write-back is ever
built (FEASIBILITY.md Option C), it goes in a SEPARATE process with a SEPARATE
key — that separation is the whole safety argument.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from .config import ItGlueConfig
from .errors import ApiError, WriteAttemptError

logger = logging.getLogger("itglue_mcp.client")

# IT Glue caps page[size] at 1000 (verified: 5000 returns the same 733 rows as
# the total-count for that resource).
MAX_PAGE_SIZE = 1000

# Substrings that must never appear in an outbound query string.
_BANNED_QUERY = ("show_password",)


class ItGlueClient:
    """Minimal read-only JSON:API client."""

    def __init__(self, cfg: ItGlueConfig) -> None:
        self._cfg = cfg
        self._base = cfg.base_url.rstrip("/")

    # ------------------------------------------------------------------ core

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> dict:
        """Perform one GET. Raises ApiError on any non-200.

        `params` keys are passed through verbatim so JSON:API bracket syntax
        (``filter[organization_id]``, ``page[size]``) survives encoding.
        """
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode(params, safe="[]")

        for banned in _BANNED_QUERY:
            if banned in query.lower() or banned in path.lower():
                raise WriteAttemptError(
                    f"Refusing a request containing {banned!r}. This server never "
                    "requests credential values. See client.py module docstring."
                )

        url = f"{self._base}{path}{query}"
        method = "GET"
        if method != "GET":  # pragma: no cover - tripwire, see docstring
            raise WriteAttemptError(f"Non-GET method {method} constructed for {path}.")

        req = urllib.request.Request(
            url,
            method=method,
            headers={
                "x-api-key": self._cfg.api_key,
                "Content-Type": "application/vnd.api+json",
                "Accept": "application/vnd.api+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._cfg.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8")[:400]
            except Exception:  # noqa: BLE001
                pass
            if exc.code == 401:
                raise ApiError(
                    "IT Glue rejected the API key (401). If this used to work, the "
                    "key may have been auto-revoked — IT Glue revokes keys unused "
                    "for 90+ days."
                ) from exc
            if exc.code == 429:
                raise ApiError(
                    "IT Glue rate limit hit (429). The documented ceiling is 3,000 "
                    "requests per 5 minutes; a mirror rebuild is the only bulk "
                    "consumer here."
                ) from exc
            raise ApiError(f"IT Glue GET {path} failed: HTTP {exc.code} {body}") from exc
        except urllib.error.URLError as exc:
            raise ApiError(f"IT Glue unreachable for GET {path}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise ApiError(f"IT Glue returned non-JSON for GET {path}.") from exc

    def get_all(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        page_size: int = MAX_PAGE_SIZE,
        max_pages: int = 50,
    ) -> List[dict]:
        """Page through a collection endpoint and return the concatenated
        ``data`` array."""
        out: List[dict] = []
        page = 1
        while page <= max_pages:
            merged = dict(params or {})
            merged["page[size]"] = min(page_size, MAX_PAGE_SIZE)
            merged["page[number]"] = page
            body = self.get(path, merged)
            batch = body.get("data") or []
            out.extend(batch)
            if len(batch) < merged["page[size]"]:
                break
            page += 1
            if self._cfg.sync_delay:
                time.sleep(self._cfg.sync_delay)
        else:
            logger.warning("get_all(%s) stopped at max_pages=%s", path, max_pages)
        return out

    def total_count(self, path: str, params: Optional[Dict[str, Any]] = None) -> int:
        merged = dict(params or {})
        merged["page[size]"] = 1
        body = self.get(path, merged)
        return int((body.get("meta") or {}).get("total-count") or 0)

    # ------------------------------------------------------- typed accessors

    def organizations(self) -> List[dict]:
        return self.get_all("/organizations")

    def configurations(self) -> List[dict]:
        return self.get_all("/configurations")

    def contacts(self) -> List[dict]:
        return self.get_all("/contacts")

    def locations(self) -> List[dict]:
        return self.get_all("/locations")

    def passwords(self) -> List[dict]:
        """Password RECORDS — metadata only.

        The list endpoint does not include a `password` attribute at all, and
        this key cannot request one (?show_password=true -> 401). redact.py
        strips the remaining sensitive fields before anything leaves the server.
        """
        return self.get_all("/passwords")

    def domains(self) -> List[dict]:
        return self.get_all("/domains")

    def expirations(self) -> List[dict]:
        return self.get_all("/expirations")

    def flexible_asset_types(self) -> List[dict]:
        return self.get_all("/flexible_asset_types")

    def flexible_assets(self, type_id: str) -> List[dict]:
        """Flexible assets for ONE type.

        A bare /flexible_assets call is a 422 — IT Glue requires the type filter.
        """
        return self.get_all("/flexible_assets", {"filter[flexible_asset_type_id]": type_id})

    def organization_documents(self, org_id: str) -> List[dict]:
        """Document LISTING for one org.

        The global /documents index 404s on this key; documents are only
        discoverable per-organization.
        """
        return self.get_all(f"/organizations/{org_id}/relationships/documents")

    def document(self, doc_id: str) -> dict:
        """One document WITH its sections.

        GET /documents/{id} works even though GET /documents does not. The prose
        lives in attributes.sections[].rendered-content as HTML.
        """
        body = self.get(f"/documents/{doc_id}")
        data = body.get("data")
        if not isinstance(data, dict):
            raise ApiError(f"Document {doc_id} returned no data object.")
        return data

    def logs(self, limit: int = 100) -> List[dict]:
        """Audit log. Retention is shallow (~500 entries) but it records
        `show Password` events with user, IP and city."""
        return self.get_all("/logs", page_size=min(limit, MAX_PAGE_SIZE), max_pages=1)

    def health(self) -> dict:
        """Cheap connectivity probe."""
        body = self.get("/organizations", {"page[size]": 1})
        return {
            "ok": True,
            "base_url": self._base,
            "organizations_visible": int((body.get("meta") or {}).get("total-count") or 0),
        }
