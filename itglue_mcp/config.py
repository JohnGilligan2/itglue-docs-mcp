"""Configuration loading and fail-fast validation.

All runtime config comes from environment variables (12-factor). For local
development you may drop a `.env` file in the working directory or point
`ITGLUE_ENV_FILE` at a file; values already present in the real environment
always win. Production (Portainer, behind Nginx Proxy Manager) injects
everything via the container environment and never ships a .env.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .errors import ConfigError


def _load_env_file(path: Path) -> None:
    """Populate os.environ from a simple KEY=VALUE file, without overriding
    variables that are already set."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


def _autoload_env_files() -> None:
    explicit = os.environ.get("ITGLUE_ENV_FILE")
    if explicit:
        _load_env_file(Path(explicit).expanduser())
    _load_env_file(Path.cwd() / ".env")


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise ConfigError(
            f"Required environment variable {name} is missing or empty. "
            f"Set it in the container environment (or a local .env)."
        )
    return val


@dataclass
class AuthConfig:
    """Client -> server auth on the public endpoint. Entra ID is the
    authorization server; this process is a pure resource server — it validates
    audience-bound tokens and never issues them."""

    enabled: bool
    tenant_id: Optional[str]
    client_id: Optional[str]
    base_url: Optional[str]
    required_scopes: List[str] = field(default_factory=list)
    scope_name: str = "access_as_user"
    # MUST equal the MCP resource indicator (this server's /mcp URL) — house
    # playbook rule 2, else AADSTS9010010.
    identifier_uri: Optional[str] = None
    # Advertise offline_access in the protected-resource metadata so Claude's
    # sign-in obtains a REFRESH token and the connector renews silently instead
    # of showing "disconnected" at access-token expiry. Never REQUIRED on
    # inbound tokens (it never appears in an access token's scp claim).
    advertise_offline_access: bool = True


@dataclass
class ItGlueConfig:
    """The IT Glue REST API. READ-ONLY by construction — see client.py.

    `api_key` here has, in the live tenant, full write and delete rights. That
    is a property of the key, not a choice: IT Glue does not scope classic API
    keys down to read. The safety guarantee is therefore entirely in this
    codebase (no mutating code path exists) plus the WriteAttemptError tripwire.
    """

    api_key: str
    # api.itglue.com (US) or api.eu.itglue.com (EU). Verified: this tenant is US.
    base_url: str = "https://api.itglue.com"
    # Tenant web UI root, used to build the human-clickable deep links that are
    # the entire point of the credential tool.
    subdomain_url: str = "https://your-company.itglue.com"
    timeout: float = 40.0
    # IT Glue documents 3,000 requests / 5 min. We stay far under it, but the
    # mirror build is the only bulk consumer so it gets a small inter-request
    # delay rather than a token bucket.
    sync_delay: float = 0.05


@dataclass
class SafetyConfig:
    """What the server is permitted to return. Defaults are the safe ones."""

    # Password VALUES are never returned under any setting — there is no code
    # path that requests or emits one, and IT Glue refuses this key anyway
    # (?show_password=true -> 401). These toggles only govern adjacent metadata.
    #
    # Password `notes` are where second factors live in practice (PINs, recovery
    # codes, security answers) — 15 of 25 sampled records had content. Never
    # returned, and not configurable.
    #
    # `username` is half a credential. Default OFF; turn on only if the team
    # decides account-name disambiguation is worth it.
    include_password_username: bool = False
    # IT Glue's own "limited visibility" marker. Records with restricted=true
    # are dropped from every result rather than reasoned about.
    honor_restricted: bool = True
    # Archived records are excluded from search results by default.
    include_archived: bool = False


@dataclass
class IndexConfig:
    """The local mirror. Required, not an optimisation: IT Glue's filter[name]
    is EXACT-MATCH ONLY (verified: filter[name]=Info returns 0 while
    filter[name]=Example Corp returns 1), and some filters are silently ignored.
    Substring/fuzzy search therefore has to happen here."""

    # Structured records (orgs, configs, contacts, locations, passwords, flex
    # assets) — ~7k rows, ~10 requests. Cheap, so refresh often.
    core_ttl_seconds: int = 6 * 3600
    # Document bodies — ~300 docs, ~400 requests (95 org listings + per-doc
    # fetches). Slower, and the corpus barely changes (9 of 300 touched in 2026).
    docs_ttl_seconds: int = 24 * 3600
    # Build the document index at startup in a background thread. Off = built
    # lazily on the first document search (that call then blocks for minutes).
    warm_docs_on_start: bool = True
    max_results: int = 25


@dataclass
class AppConfig:
    auth: AuthConfig
    itglue: ItGlueConfig
    safety: SafetyConfig
    index: IndexConfig
    host: str = "0.0.0.0"
    port: int = 8000


def load_config() -> AppConfig:
    """Load + validate everything. Raises ConfigError on the first missing
    required value so the container dies loudly at startup rather than on the
    first tool call."""
    _autoload_env_files()

    auth = AuthConfig(
        enabled=_bool("MCP_AUTH_ENABLED", default=True),
        tenant_id=os.environ.get("ENTRA_TENANT_ID") or os.environ.get("AZURE_TENANT_ID"),
        client_id=os.environ.get("ENTRA_CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID"),
        base_url=(os.environ.get("MCP_BASE_URL") or "").rstrip("/") or None,
        required_scopes=[
            s.strip()
            for s in os.environ.get("ENTRA_REQUIRED_SCOPES", "").split(",")
            if s.strip()
        ],
        scope_name=os.environ.get("ENTRA_SCOPE_NAME", "access_as_user"),
        identifier_uri=os.environ.get("ENTRA_IDENTIFIER_URI") or None,
        advertise_offline_access=_bool("ITGLUE_ADVERTISE_OFFLINE_ACCESS", default=True),
    )
    if auth.enabled:
        missing = [
            label
            for label, val in (
                ("ENTRA_TENANT_ID", auth.tenant_id),
                ("ENTRA_CLIENT_ID", auth.client_id),
                ("MCP_BASE_URL", auth.base_url),
            )
            if not val
        ]
        if missing:
            raise ConfigError(
                "Client auth is enabled but these are missing: "
                f"{', '.join(missing)}. Either set them, or set "
                "MCP_AUTH_ENABLED=false for local Inspector testing only "
                "(never in production)."
            )

    itglue = ItGlueConfig(
        api_key=_require("ITGLUE_API_KEY"),
        base_url=(os.environ.get("ITGLUE_BASE_URL") or "https://api.itglue.com").rstrip("/"),
        subdomain_url=(
            os.environ.get("ITGLUE_SUBDOMAIN_URL")
            or "https://your-company.itglue.com"
        ).rstrip("/"),
        timeout=float(os.environ.get("ITGLUE_TIMEOUT", "40")),
        sync_delay=float(os.environ.get("ITGLUE_SYNC_DELAY", "0.05")),
    )

    safety = SafetyConfig(
        include_password_username=_bool("ITGLUE_INCLUDE_USERNAME", default=False),
        honor_restricted=_bool("ITGLUE_HONOR_RESTRICTED", default=True),
        include_archived=_bool("ITGLUE_INCLUDE_ARCHIVED", default=False),
    )

    index = IndexConfig(
        core_ttl_seconds=_int("ITGLUE_CORE_TTL", 6 * 3600),
        docs_ttl_seconds=_int("ITGLUE_DOCS_TTL", 24 * 3600),
        warm_docs_on_start=_bool("ITGLUE_WARM_DOCS_ON_START", default=True),
        max_results=_int("ITGLUE_MAX_RESULTS", 25),
    )

    return AppConfig(
        auth=auth,
        itglue=itglue,
        safety=safety,
        index=index,
        host=os.environ.get("MCP_HOST", "0.0.0.0"),
        port=_int("MCP_PORT", 8000),
    )
