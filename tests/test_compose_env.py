"""Guard the compose file against the failure that broke the first deploy.

    ConfigError: Client auth is enabled but these are missing:
    ENTRA_TENANT_ID, ENTRA_CLIENT_ID, MCP_BASE_URL

Cause: docker-compose.yml referenced `${ENTRA_TENANT_ID}` with no default, so
Portainer substituted an empty string and the container died at startup. The
values HAD been inlined — but into a second, duplicate stack file that Portainer
never read. Two files that must stay in sync is a trap; there is now one.

These checks are static (no network, no Docker, no fastmcp) so they can run
anywhere:

  1. Every environment variable config.py reads appears in docker-compose.yml.
     A var the code reads but compose omits silently falls back to the code
     default — or, if required, crashes the container.
  2. Every ${VAR} in compose either has a `:-default` or is deliberately
     required. Only ITGLUE_API_KEY may be required, because a server with no key
     genuinely cannot do anything and should fail loudly.
  3. The stack therefore deploys with ITGLUE_API_KEY as the ONLY Portainer stack
     environment variable — which is what the deploy doc promises.
  4. There is exactly one compose file, so this can't drift again.

Run:  python tests/test_compose_env.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
CONFIG = ROOT / "itglue_mcp" / "config.py"

# Read by the code but intentionally absent from compose.
EXEMPT_FROM_COMPOSE = {
    # Local-dev escape hatch (points at a .env file). Must never be set in a
    # deployed stack, so it deliberately has no compose entry.
    "ITGLUE_ENV_FILE",
    # Fallback ALIASES, not separate settings: config.py reads
    # `ENTRA_TENANT_ID or AZURE_TENANT_ID`. The ENTRA_* primaries are what
    # compose sets; the AZURE_* names exist only to accept the other common
    # spelling if someone injects it. Requiring them in compose would be wrong.
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
}

# The only variable allowed to have no default in compose.
MAY_BE_REQUIRED = {"ITGLUE_API_KEY"}

PASS, FAIL = 0, 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}{(chr(10) + '        ' + detail) if detail else ''}")


compose_text = COMPOSE.read_text(encoding="utf-8")
config_text = CONFIG.read_text(encoding="utf-8")

# --- 1. every env var the code reads is present in compose -------------------
# Matches os.environ.get("X"), os.environ["X"], and the _bool/_int/_require
# helpers, all of which take the variable name as their first string argument.
code_vars = set(re.findall(r'os\.environ(?:\.get)?\(\s*"([A-Z0-9_]+)"', config_text))
code_vars |= set(re.findall(r'os\.environ\[\s*"([A-Z0-9_]+)"\s*\]', config_text))
code_vars |= set(re.findall(r'\b_(?:bool|int|require)\(\s*"([A-Z0-9_]+)"', config_text))
code_vars -= EXEMPT_FROM_COMPOSE

print(f"=== {len(code_vars)} env vars read by config.py ===")
missing = sorted(v for v in code_vars if v not in compose_text)
check(
    "every env var config.py reads appears in docker-compose.yml",
    not missing,
    f"missing from compose: {', '.join(missing)}" if missing else "",
)

# --- 2. no ${VAR} without a default, except the API key ----------------------
refs = re.findall(r"\$\{([A-Z0-9_]+)(:-[^}]*)?\}", compose_text)
no_default = sorted({name for name, default in refs if not default} - MAY_BE_REQUIRED)
print(f"=== {len(refs)} \\${{VAR}} references in compose ===")
check(
    "no ${VAR} lacks a default except ITGLUE_API_KEY",
    not no_default,
    f"these would substitute to empty and crash the container: {', '.join(no_default)}"
    if no_default else "",
)

# --- 3. the values that actually broke the deploy are pinned -----------------
for var, expected in [
    ("ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
    ("ENTRA_CLIENT_ID", "00000000-0000-0000-0000-000000000000"),
    ("MCP_BASE_URL", "https://itglue-mcp.example.com"),
    ("ENTRA_IDENTIFIER_URI", "https://itglue-mcp.example.com/mcp"),
]:
    m = re.search(rf"\$\{{{var}:-([^}}]*)\}}", compose_text)
    check(f"{var} defaults to the provisioned value", bool(m) and m.group(1) == expected,
          f"got {m.group(1) if m else 'NO DEFAULT'!r}, expected {expected!r}")

# The App ID URI must be MCP_BASE_URL + /mcp or sign-in fails AADSTS9010010.
base = re.search(r"\$\{MCP_BASE_URL:-([^}]*)\}", compose_text)
ident = re.search(r"\$\{ENTRA_IDENTIFIER_URI:-([^}]*)\}", compose_text)
check(
    "ENTRA_IDENTIFIER_URI == MCP_BASE_URL + '/mcp' (else AADSTS9010010)",
    bool(base and ident) and ident.group(1) == base.group(1).rstrip("/") + "/mcp",
    f"{ident.group(1) if ident else None} vs {base.group(1) if base else None}",
)

# --- 4. safety defaults must not drift open ---------------------------------
for var, expected in [
    ("ITGLUE_INCLUDE_USERNAME", "false"),
    ("ITGLUE_HONOR_RESTRICTED", "true"),
    ("ITGLUE_INCLUDE_ARCHIVED", "false"),
    ("MCP_AUTH_ENABLED", "true"),
    ("ITGLUE_ADVERTISE_OFFLINE_ACCESS", "true"),
]:
    m = re.search(rf"\$\{{{var}:-([^}}]*)\}}", compose_text)
    check(f"{var} defaults to {expected}", bool(m) and m.group(1) == expected,
          f"got {m.group(1) if m else 'NO DEFAULT'!r}")

# --- 5. structural guards ----------------------------------------------------
check("pull_policy: build is set (else Portainer redeploy tries a registry pull)",
      "pull_policy: build" in compose_text)
check("host port 8111", re.search(r'"\$\{MCP_HOST_PORT:-8111\}:8000"', compose_text) is not None)
check("no client secret in compose (resource-server mode needs none)",
      not re.search(r"CLIENT_SECRET|client_secret", compose_text))
check("no literal IT Glue key committed", "ITG." not in compose_text)

others = [p for p in (ROOT / "deploy").glob("*.y*ml")] if (ROOT / "deploy").is_dir() else []
check("exactly one compose file — no duplicate stack file to drift out of sync",
      not others, f"also found: {[p.name for p in others]}")

print(f"\n=== RESULT ===\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
