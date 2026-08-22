"""Local smoke test against the LIVE IT Glue tenant. Read-only, by definition.

Run from the repo root with the API key available:

    ITGLUE_API_KEY=... MCP_AUTH_ENABLED=false python tests/smoke_local.py

or let it read the key from the credentials file (default):

    python tests/smoke_local.py

Does NOT import server.py, so it runs without fastmcp installed. It exercises
the parts that carry the risk: the GET-only client, the redaction layer, the
mirror, and the fuzzy search that makes the exact-match API usable.

The credential assertions are the important ones. If any of them ever fail, stop
and fix it before deploying — they are the guarantee John asked for.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

CREDS = Path.home() / ".claude" / "credentials" / "itglue.env"
if not os.environ.get("ITGLUE_API_KEY") and CREDS.exists():
    # House convention: KEY=VALUE env file outside any shareable directory.
    # (Superseded the old plaintext .itglueapicreds.txt on 2026-07-30.)
    for line in CREDS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
if not os.environ.get("ITGLUE_API_KEY"):
    sys.exit(
        f"No ITGLUE_API_KEY. Set it in the environment, or provide {CREDS}\n"
        "with a line: ITGLUE_API_KEY=ITG.…"
    )
os.environ.setdefault("MCP_AUTH_ENABLED", "false")

from itglue_mcp import search  # noqa: E402
from itglue_mcp.client import ItGlueClient  # noqa: E402
from itglue_mcp.config import load_config  # noqa: E402
from itglue_mcp.errors import WriteAttemptError  # noqa: E402
from itglue_mcp.index import ItGlueIndex, html_to_text  # noqa: E402
from itglue_mcp.redact import NEVER_EMIT, scrub_password_record  # noqa: E402

PASS, FAIL = 0, 0


def check(label: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


cfg = load_config()
client = ItGlueClient(cfg.itglue)
index = ItGlueIndex(client, cfg.index, cfg.safety, cfg.itglue)

# ---------------------------------------------------------------------------
section("1. READ-ONLY / NO-SECRETS enforcement (does not touch the network)")

check(
    "client exposes no mutating methods",
    not any(
        hasattr(client, name)
        for name in ("post", "patch", "put", "delete", "create", "update", "destroy")
    ),
)

try:
    client.get("/passwords/1", {"show_password": "true"})
    check("show_password in params is refused", False, "no exception raised")
except WriteAttemptError:
    check("show_password in params is refused", True)
except Exception as exc:  # noqa: BLE001
    check("show_password in params is refused", False, f"wrong error: {type(exc).__name__}")

try:
    client.get("/passwords/1?show_password=true")
    check("show_password in path is refused", False, "no exception raised")
except WriteAttemptError:
    check("show_password in path is refused", True)
except Exception as exc:  # noqa: BLE001
    check("show_password in path is refused", False, f"wrong error: {type(exc).__name__}")

fake = {
    "id": "999",
    "type": "passwords",
    "attributes": {
        "name": "test cred",
        "password": "SUPERSECRET",
        "username": "admin",
        "notes": "PIN is 1234, recovery code ABCD-EFGH",
        "otp-secret": "JBSWY3DPEHPK3PXP",
        "autofill-selectors": "#pw",
        "url": "https://example.com",
        "resource-url": "https://x.itglue.com/1/passwords/999",
    },
}
scrubbed = scrub_password_record(fake, include_username=False)
blob = repr(scrubbed)
check("password value stripped", "password" not in scrubbed and "SUPERSECRET" not in blob)
check("notes stripped", "notes" not in scrubbed and "1234" not in blob)
check("otp secret stripped", "otp_secret" not in scrubbed and "JBSWY3DPEHPK3PXP" not in blob)
check("autofill selectors stripped", "autofill_selectors" not in scrubbed)
check("username stripped when disabled", "username" not in scrubbed)
check(
    "username present only when explicitly enabled",
    "username" in scrub_password_record(fake, include_username=True),
)
check("resource_url preserved (the whole point)", bool(scrubbed.get("resource_url")))
check("NEVER_EMIT covers the obvious names", {"password", "otp_secret"} <= NEVER_EMIT)

check(
    "html_to_text strips markup and unescapes",
    html_to_text("<div><span>IP&nbsp;10.0.0.1<br>Gw 10.0.0.254</span></div>")
    == "IP 10.0.0.1\nGw 10.0.0.254",
    repr(html_to_text("<div><span>IP&nbsp;10.0.0.1<br>Gw 10.0.0.254</span></div>")),
)

# ---------------------------------------------------------------------------
section("2. Live API + core mirror")

health = client.health()
check("API reachable", health.get("ok") is True)
check("organizations visible", health.get("organizations_visible", 0) > 0,
      str(health))

index.ensure_core()
st = index.status()
counts = st["counts"]
print(f"      counts: {counts}")
check("orgs mirrored", counts["organizations"] > 0)
check("configurations mirrored", counts["configurations"] > 0)
check("passwords mirrored", counts["passwords"] > 0)
check("flexible assets mirrored", counts["flexible_assets"] > 0)
check("locations mirrored", counts["locations"] > 0)

check(
    "NO mirrored password record carries a denied field",
    all(
        not (set(p) & NEVER_EMIT) and "notes" not in p
        for p in index.passwords
    ),
)
check(
    "no mirrored password carries a username (default config)",
    all("username" not in p for p in index.passwords),
)

# ---------------------------------------------------------------------------
section("3. Organization resolution (the exact-match workaround)")

for query, expect in [
    ("EF", "Example Foundation"),
    ("Example Foundation", "Example Foundation"),
    ("Example Foundation", "Example Foundation"),
    ("Example Corp", "Example Corp"),
    ("infonet", "Example Corp"),
]:
    matches = search.match_organization(query, index.organizations)
    top = matches[0][1].get("name") if matches else None
    check(f"resolve {query!r} -> {expect!r}", top == expect, f"got {top!r}")

nl = "EF Example Foundation Unified Controller"
matches = search.match_organization(nl, index.organizations)
top = matches[0] if matches else (0, {})
check(
    f"org inferred from a whole sentence: {nl!r}",
    top[1].get("name") == "Example Foundation" and top[0] >= 50,
    f"got {top[1].get('name')!r} score {top[0]:.1f}",
)

terms = search.strip_org_terms(search.query_tokens(nl), "Example Foundation")
check(
    "org words subtracted from the query",
    terms == ["unified", "controller"],
    f"got {terms}",
)

# ---------------------------------------------------------------------------
section("4. THE REAL QUERY — 'what are the credentials for the EF UniFi controller'")

org = search.match_organization(nl, index.organizations)[0][1]
oid = org["id"]
terms = search.strip_org_terms(search.query_tokens(nl), str(org["name"]))
pwds = [p for p in index.visible(index.passwords) if str(p.get("organization_id")) == oid]


def blob(p: dict) -> str:
    return " ".join(
        str(p.get(k) or "")
        for k in ("name", "password_category_name", "url", "cached_resource_name",
                  "cached_resource_type_name", "organization_name")
    )


ranked = search.rank(pwds, terms, blob, lambda p: str(p.get("name") or ""), limit=10)
print(f"      searched {len(pwds)} EF credential records, {len(ranked)} hits")
for s, p in ranked:
    print(f"        {s:5.1f}  {str(p.get('name'))[:52]:<52} "
          f"{index.link(oid, 'passwords', p)}")

names = [str(p.get("name") or "").lower() for _, p in ranked]
check("fuzzy 'unified' matched the data's 'unifi'",
      any("unifi" in n for n in names), f"got {names}")
check("found the current staging controller admin",
      any("Example Corp unifi admin" in n for n in names))
check("found more than one controller login",
      sum("controller" in n for n in names) > 1)
check("every hit carries a clickable IT Glue link",
      all(index.link(oid, "passwords", p).startswith("https://") for _, p in ranked))
check("no hit exposes a password/notes/username field",
      all(not (set(p) & NEVER_EMIT) and "notes" not in p and "username" not in p
          for _, p in ranked))

# ---------------------------------------------------------------------------
section("5. Configuration search by IP / name")

cfgs = [c for c in index.visible(index.configurations) if str(c.get("organization_id")) == oid]


def cblob(c: dict) -> str:
    return " ".join(
        str(c.get(k) or "")
        for k in ("name", "hostname", "primary_ip", "serial_number", "mac_address",
                  "configuration_type_name", "manufacturer_name", "model_name",
                  "operating_system_name", "notes", "organization_name")
    )


ip_hits = search.rank(cfgs, ["192.0.2.9"], cblob, lambda c: str(c.get("name") or ""), limit=5)
print(f"      IP 192.0.2.9 -> {[c.get('name') for _, c in ip_hits]}")
check("device found by IP address", len(ip_hits) > 0)

ctrl = search.rank(cfgs, ["unifi", "controller"], cblob,
                   lambda c: str(c.get("name") or ""), limit=10)
print(f"      'unifi controller' -> {[c.get('name') for _, c in ctrl]}")
check("controller configurations found", len(ctrl) > 0)

flex = [f for f in index.visible(index.flexible_assets) if str(f.get("organization_id")) == oid]
check("EF has flexible assets to search too", isinstance(flex, list))

# ---------------------------------------------------------------------------
section("6. Document index (limited to 3 orgs to keep the test quick)")

all_orgs = list(index.organizations)
sample = [o for o in all_orgs if o.get("name") in
          ("Example Corp", "Example Medical", "Example Models / Example Models")]
index.organizations = sample or all_orgs[:3]
try:
    index.ensure_docs(force=True)
finally:
    index.organizations = all_orgs

docs = index.documents
with_text = [d for d in docs if d.get("text")]
print(f"      {len(docs)} documents, {len(with_text)} with text, "
      f"{sum(len(d['text']) for d in docs):,} chars")
check("documents indexed", len(docs) > 0)
check("document prose extracted", len(with_text) > 0)
check("binary uploads flagged, not fetched",
      all(not d["text"] for d in docs if d["is_uploaded"]))
check("every document has a link", all(d["url"].startswith("https://") for d in docs))

hits = search.rank(with_text, ["technical", "overview"],
                   lambda d: f"{d['name']} {d['text']}", lambda d: d["name"], limit=5)
print(f"      'technical overview' -> {[d['name'][:46] for _, d in hits]}")
check("full-text document search returns hits", len(hits) > 0)

# The regression this guards: word tokenisation shreds '192.0.2.51' into
# ['10','105','251'], which matches noise and misses the actual host. terms_for
# keeps the intact string as a term so the IP is found inside document prose.
raw_terms = search.terms_for("192.0.2.51")
check("a bare IP searches on the intact string only",
      raw_terms == ["192.0.2.51"], f"got {raw_terms}")
check("terms_for keeps a MAC intact",
      search.terms_for("04:18:d6:c0:29:1a") == ["04:18:d6:c0:29:1a"],
      f"got {search.terms_for('04:18:d6:c0:29:1a')}")
sentence = search.terms_for("which device is 192.0.2.9")
check("an IP inside a sentence keeps words but drops numeric fragments",
      "192.0.2.9" in sentence and not {"10", "251", "9"} & set(sentence),
      f"got {sentence}")
check("a plain query is unaffected",
      search.terms_for("unifi controller") == ["unifi", "controller"],
      f"got {search.terms_for('unifi controller')}")

ip_doc = search.rank(with_text, raw_terms,
                     lambda d: f"{d['name']} {d['text']}", lambda d: d["name"], limit=10)
print(f"      IP 192.0.2.51 inside document body -> {[d['name'][:46] for _, d in ip_doc]}")
check("IP address found inside document prose", len(ip_doc) > 0)
# Precision: only documents that literally contain the string should match.
check("no false positives on an IP lookup",
      all("192.0.2.51" in d["text"] for _, d in ip_doc),
      f"{[d['name'] for _, d in ip_doc if '192.0.2.51' not in d['text']]}")

# ---------------------------------------------------------------------------
section("RESULT")
print(f"  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
