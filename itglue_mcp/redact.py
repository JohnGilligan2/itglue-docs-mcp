"""Output redaction — the second half of the credential guarantee.

client.py makes it impossible to *request* a password value. This module makes
it impossible to *emit* one, plus the adjacent fields that are effectively
credential material:

  password / password_value  — never present on this key anyway; belt and braces.
  notes                      — on password records this is where second factors
                               live in practice (PINs, recovery codes, security
                               answers). 15 of 25 sampled records had content.
                               Always stripped, not configurable.
  otp_secret / autofill      — TOTP seed and selector material.
  username                   — half a credential. Off by default; see
                               SafetyConfig.include_password_username.

Everything the credential tool returns is a POINTER: which credential exists,
where it lives, when it last rotated, and the IT Glue URL to open. The secret
itself is only ever revealed by IT Glue to a signed-in human.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# Attribute names (normalised to snake_case) that must never reach a response
# from ANY resource type, whatever a future tool does.
NEVER_EMIT = frozenset(
    {
        "password",
        "password_value",
        "password_plaintext",
        "secret",
        "otp_secret",
        "otp_seed",
        "totp_secret",
        "private_key",
        "autofill_selectors",
    }
)

# Additionally stripped from PASSWORD records specifically.
NEVER_EMIT_ON_PASSWORDS = frozenset({"notes"})


def norm_key(key: str) -> str:
    """IT Glue returns kebab-case attribute names; we work in snake_case."""
    return key.replace("-", "_")


def attrs(record: dict) -> Dict[str, Any]:
    """Flatten a JSON:API record's attributes into a snake_case dict, with the
    global denylist already applied, plus `id` and `type`."""
    out: Dict[str, Any] = {}
    for key, val in (record.get("attributes") or {}).items():
        nk = norm_key(key)
        if nk in NEVER_EMIT:
            continue
        out[nk] = val
    out["id"] = str(record.get("id") or "")
    out["_type"] = record.get("type") or ""
    return out


def scrub_password_record(record: dict, include_username: bool = False) -> Dict[str, Any]:
    """Turn a raw IT Glue password record into a safe pointer dict.

    This is the ONLY function that should ever shape a password for output.
    """
    a = attrs(record)
    for banned in NEVER_EMIT_ON_PASSWORDS:
        a.pop(banned, None)
    if not include_username:
        a.pop("username", None)
    return a


def is_visible(record_attrs: Dict[str, Any], honor_restricted: bool, include_archived: bool) -> bool:
    """Apply IT Glue's own visibility markers.

    `restricted` is IT Glue's native limited-visibility flag; we drop those
    records rather than reason about who may see them. `archived` records are
    stale by definition and excluded from search unless explicitly requested.
    """
    if honor_restricted and bool(record_attrs.get("restricted")):
        return False
    if not include_archived and bool(record_attrs.get("archived")):
        return False
    return True


def itglue_link(
    subdomain_url: str,
    org_id: Optional[str],
    kind: str,
    record_id: str,
    resource_url: Optional[str] = None,
) -> str:
    """Prefer IT Glue's own `resource-url`; fall back to composing one.

    `kind` is the UI path segment: passwords, configurations, contacts,
    locations, docs.
    """
    if resource_url:
        return str(resource_url)
    base = subdomain_url.rstrip("/")
    if org_id:
        return f"{base}/{org_id}/{kind}/{record_id}"
    return f"{base}/{kind}/{record_id}"
