# itglue-mcp

Read-only MCP server over the Example Corp / examplecorp IT Glue tenant
(`your-company.itglue.com`). Answers "what do we know about this
customer" from chat, and answers "what are the credentials for X" with an
**IT Glue link** rather than a secret.

Built on the house remote-MCP standard: `fastmcp` resource server + Entra ID
auth, behind Nginx Proxy Manager on Portainer. See
[`~/.claude/context/mcp-server-playbook.md`](../../.claude/context/mcp-server-playbook.md).

Findings from the API and content audit that shaped this design are in
[FEASIBILITY.md](FEASIBILITY.md). Read §0 and §1 before changing anything.

---

## The two guarantees

### 1. Nothing is ever written to IT Glue

The API key in use has **full write and delete rights.** Verified, not assumed:

```
PATCH  /configurations/999999999  -> 404 "Record not found"
PATCH  /passwords/999999999       -> 404 "Record not found"
DELETE /configurations/999999999  -> 404
```

A key without write permission fails 401/403 *before* the record lookup. A 404
means the mutation was authorized and merely had nothing to act on. IT Glue does
not issue read-scoped classic API keys, so **there is no server-side permission
to lean on** — the guarantee is entirely in this codebase:

- [`client.py`](itglue_mcp/client.py) exposes exactly one request method,
  `get()`, which hardcodes `method="GET"`.
- No `post`/`patch`/`put`/`delete` helper exists. Adding one is a security
  regression, not a feature.
- A `WriteAttemptError` tripwire fires if a non-GET is ever constructed.
- `tests/smoke_local.py` asserts both the absent methods and the absent verbs.

If write-back is ever built (FEASIBILITY.md Option C), it goes in a **separate
process with a separate key.** That separation is the whole safety argument,
because IT Glue documents are customer-authored text that a model summarises —
i.e. untrusted input.

### 2. No credential value is ever returned

`itglue_find_credential` returns a **pointer**: the credential's name, category,
which device it belongs to, when it last rotated, whether OTP is on, and an
IT Glue deep link. The human clicks the link and signs in to IT Glue to reveal
the secret.

| Field | Returned? | Why |
|---|---|---|
| `password` | **Never** | Not configurable. IT Glue also refuses this key a value (`?show_password=true` → **401**). |
| `notes` | **Never** | Not configurable. In this tenant, 15 of 25 sampled records had notes, and password notes are where PINs and recovery codes live. |
| `otp_secret`, `autofill_selectors` | **Never** | TOTP seed / selector material. |
| `username` | Off by default | Half a credential. `ITGLUE_INCLUDE_USERNAME=true` to enable. |
| `resource_url` | Yes | This is the deliverable. |

Redaction happens on the way **into** the mirror
([`redact.py`](itglue_mcp/redact.py)), so no downstream tool can leak a field by
forgetting to strip it. Records IT Glue marks `restricted` are dropped entirely.

---

## Why there's a local mirror

**IT Glue's `filter[name]` is exact-match only,** and some filters are silently
ignored rather than rejected:

| Query | Result |
|---|---|
| `filter[name]=Example Corp` | 1 |
| `filter[name]=Info` | **0** |
| `filter[name]=nfoN` | **0** |
| `/contacts?filter[name]=john` | **all 318 contacts** (filter ignored) |

So server-side search either needs the exact string the model doesn't have, or
quietly lies. Everything is therefore mirrored into RAM and searched locally
([`search.py`](itglue_mcp/search.py), [`index.py`](itglue_mcp/index.py)).

Sync cost, measured: **~10 requests** for ~7,000 structured records; **~400
requests** for 300 document bodies (95 org listings + per-doc fetches), against a
ceiling of 3,000 per 5 minutes. Core warms in seconds; documents warm in the
background over a few minutes, and document tools report `status: indexing`
instead of hanging.

Nothing is persisted to disk — the corpus is small, so a restart just re-syncs
and there's no stale-cache failure mode.

Search is deliberately forgiving because real queries look like *"EF Example
Foundation Unified Controller"*: an acronym, a full name, and a product spelled
**Unifi** in the data. Handled by acronym matching (`EF` → Example Foundation),
per-word fuzzy matching (`unified` ≈ `unifi`, ratio 0.83), org-token subtraction,
and atomic identifier handling so `192.0.2.51` isn't shredded into
`['10','105','251']`.

---

## Tools

| Tool | What it does |
|---|---|
| `itglue_find_organization` | Resolve a name/acronym/fragment to organizations. Use first when ambiguous. |
| `itglue_find_credential` | **Which** credentials exist for a device/service + IT Glue links. Never a value. |
| `itglue_search_documents` | Full-text search across document bodies. Returns snippet + last-updated date + link. |
| `itglue_get_document` | One document's full text, HTML → plain text. |
| `itglue_find_configuration` | Device by name, hostname, IP, serial or MAC. Searches configurations **and** flexible assets. |
| `itglue_organization_brief` | Whole customer in one call: sites, contacts, device counts, documents, domains, expirations. |
| `itglue_list_locations` | Street addresses, postal codes, phones. The cleanest data in the tenant (79% complete). |
| `itglue_list_contacts` | Emails, phones, titles; `important_only` filter. |
| `itglue_expirations` | Warranties, SSL, domains — expiring or overdue. |
| `itglue_documentation_health` | Gap report, worst-first: missing fields, no site address, no Technical Overview Sheet, credentials unrotated 3+ years. |
| `itglue_health_check` | Connectivity, mirror freshness, safety posture. Run this first when something looks off. |

All are annotated `readOnlyHint: true`.

### The query this was built for

> *"What are the credentials for the Example Foundation UniFi controller?"*

`itglue_find_credential` infers the org from the sentence, subtracts its name
words, fuzzy-matches `unified`→`unifi` across the org's credential records, and
returns a pointer for each matching login, current and older controllers alike,
each with a clickable link, the
device URL, and the last-rotated date. No secret leaves the server.

---

## Local development

```bash
python -m venv .venv && .venv/Scripts/activate    # Windows
pip install -r requirements.txt
cp .env.example .env      # fill in ITGLUE_API_KEY; set MCP_AUTH_ENABLED=false
python -m itglue_mcp
```

Never expose an auth-off server. `MCP_AUTH_ENABLED=false` is for MCP Inspector
on localhost only.

### Smoke test (live, read-only)

```bash
python tests/smoke_local.py
```

47 assertions against the live tenant. Reads `~/.claude/credentials/itglue.env`
if `ITGLUE_API_KEY` isn't set in the environment, and needs no fastmcp install.
The credential assertions are the important ones — if any fail, stop and fix
before deploying.

---

## Deploy

1. **Entra app + group + token lifetime** — `scripts/setup_entra_app.ps1`
   (dry-run by default; `-Apply` to execute). Provisions the app, the
   `ITGlue-MCP-Users` security group with the five initial members, assignment
   enforcement, and a **23h59m access-token lifetime policy**. See
   [docs/ENTRA_SETUP_CHECKLIST.md](docs/ENTRA_SETUP_CHECKLIST.md).
2. **Portainer stack + NPM** — [PORTAINER_DEPLOY.md](PORTAINER_DEPLOY.md).
   Host port **8111** (probed free on `10.0.0.10`, 2026-07-29 — 8100 and 8110
   are in use). Public host `itglue-mcp.example.com`.

## Housekeeping

- **Rotate the IT Glue key — still outstanding.** It now lives at
  `~/.claude/credentials/itglue.env` in house `KEY=VALUE` format (migrated
  2026-07-30 from a plaintext `.itglueapicreds.txt`), but **that was a format
  change, not a rotation — the key value is unchanged.** It has write + delete
  rights and sat in a plaintext `.txt` for an unknown period. To rotate: mint a
  new key in IT Glue → Account → Settings → API Keys, update `itglue.env` and
  the Portainer stack's `ITGLUE_API_KEY`, then revoke the old one.
- IT Glue **auto-revokes API keys unused for 90+ days.** The mirror refresh keeps
  this one warm; if the server is ever parked, expect a 401 on wake.
- Add and remove access via the `ITGlue-MCP-Users` group, not the code.
