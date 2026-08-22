"""Local fuzzy search — the reason a mirror exists at all.

IT Glue's `filter[name]` is EXACT MATCH ONLY. Verified against the live tenant:

    filter[name]=Example Corp   -> 1 result
    filter[name]=Info           -> 0 results
    filter[name]=nfoN           -> 0 results

and worse, some filters are silently IGNORED rather than rejected —
`/contacts?filter[name]=john` returned all 318 contacts. So server-side
filtering cannot be trusted for search: it either needs the exact string (which
the model does not have) or quietly lies.

Everything here therefore operates over the in-memory mirror.

Matching is deliberately forgiving because real queries look like
"EF Example Foundation Unified Controller" — an org name, an abbreviation, and a
product name that is spelled "Unifi" in the data. Handled by:

  * substring match on the whole blob (cheap, catches most things)
  * per-word fuzzy match via difflib for near-misses ("unified" ~ "unifi",
    ratio 0.83)
  * acronym match so "EF" resolves "Example Foundation"
  * org-token subtraction: once an org is resolved, its name words are removed
    from the query so they don't dilute scoring of the remaining terms
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

_WORD = re.compile(r"[a-z0-9]+")

# Words that carry no discriminating power in an MSP documentation query.
STOPWORDS = frozenset(
    {
        "the", "a", "an", "and", "or", "for", "of", "to", "in", "on", "at", "is",
        "what", "whats", "which", "who", "where", "credentials", "credential",
        "password", "passwords", "login", "logins", "account", "accounts",
        "please", "need", "get", "find", "me", "my", "our", "their", "s",
    }
)

# Near-miss ratio above which two words count as the same term.
FUZZY_THRESHOLD = 0.80


def tokens(text: str) -> List[str]:
    return _WORD.findall((text or "").lower())


def query_tokens(text: str) -> List[str]:
    """Tokenise a natural-language query, dropping noise words."""
    return [t for t in tokens(text) if t not in STOPWORDS and len(t) > 1]


def acronym(name: str) -> str:
    """First letter of each word: 'Example Foundation' -> 'ef'."""
    return "".join(w[0] for w in tokens(name))


# IPs, MACs, and hyphenated model/serial strings: runs of alphanumerics joined
# by . : - _ or /. Requires 3+ groups for the dotted/colon form so ordinary
# sentence punctuation doesn't qualify.
_IDENTIFIER = re.compile(
    r"(?:[0-9a-f]{1,4}(?:[.:][0-9a-f]{1,4}){2,}"      # 192.0.2.51, 04:18:d6:c0:29:1a
    r"|[a-z0-9]+(?:[-_/][a-z0-9]+)+)",                 # IR-ADV, AIR-CT2504-K9
    re.I,
)


def terms_for(query: str) -> List[str]:
    """Query terms for a search, treating identifiers as atomic.

    Word tokenisation shreds '192.0.2.51' into ['10','105','251']. Those
    fragments match a lot of unrelated text — asking for one host's IP returned
    five documents, only two of which contained it. So identifiers are extracted
    intact and their fragments REMOVED, which is what makes an IP or MAC lookup
    precise instead of merely non-empty.

    A query that is nothing but an identifier searches on that alone.
    """
    raw = (query or "").strip().lower()
    idents = [m.group(0) for m in _IDENTIFIER.finditer(raw)]

    # 'what is 192.0.2.9' keeps the words; a bare '192.0.2.9' should not dilute
    # a precise match with anything.
    if idents and idents[0] == raw:
        return [raw]

    terms = query_tokens(query)
    if idents:
        fragments = {frag for ident in idents for frag in tokens(ident)}
        terms = [t for t in terms if t not in fragments]
        terms.extend(idents)
    return terms or idents


def _word_fuzzy_hit(term: str, blob_words: Sequence[str]) -> bool:
    for w in blob_words:
        # Cheap length gate before the O(n*m) ratio.
        if abs(len(w) - len(term)) > 3:
            continue
        if SequenceMatcher(None, term, w).ratio() >= FUZZY_THRESHOLD:
            return True
    return False


def score(query_terms: Sequence[str], blob: str, *, boost: str = "") -> float:
    """Score one record's searchable text against the query terms.

    `boost` is a subset of the blob (usually the record's name) where a hit
    counts for more — a match in the title beats a match in a notes field.
    Returns 0.0 when too few terms matched to be meaningful.
    """
    if not query_terms:
        return 0.0
    blob_l = blob.lower()
    boost_l = (boost or "").lower()
    blob_words = tokens(blob_l)

    hits = 0
    total = 0.0
    for term in query_terms:
        if term in blob_l:
            total += 3.0
            if term in boost_l:
                total += 2.0
            hits += 1
        elif _word_fuzzy_hit(term, blob_words):
            total += 1.5
            if _word_fuzzy_hit(term, tokens(boost_l)):
                total += 1.0
            hits += 1

    # Require a real share of the query to have landed. Without this, a single
    # common word ("server") drags in half the tenant.
    needed = 1 if len(query_terms) == 1 else max(2, (len(query_terms) + 1) // 2)
    if hits < needed:
        return 0.0
    # Normalise slightly by query length so long queries don't always outrank.
    return total / (len(query_terms) ** 0.5)


def rank(
    records: Iterable[dict],
    query_terms: Sequence[str],
    blob_of: Callable[[dict], str],
    name_of: Optional[Callable[[dict], str]] = None,
    limit: int = 25,
) -> List[Tuple[float, dict]]:
    """Score, filter and sort records. Ties break on name for stable output."""
    scored: List[Tuple[float, dict]] = []
    for rec in records:
        s = score(query_terms, blob_of(rec), boost=name_of(rec) if name_of else "")
        if s > 0:
            scored.append((s, rec))
    scored.sort(key=lambda pair: (-pair[0], (name_of(pair[1]) if name_of else "").lower()))
    return scored[:limit]


def match_organization(
    query: str, orgs: Sequence[Dict], name_key: str = "name"
) -> List[Tuple[float, Dict]]:
    """Resolve a free-text org reference to candidate organizations.

    Handles exact name, substring, acronym ('EF'), short-name, and fuzzy.
    Sorted best-first; callers normally take the top hit but should surface the
    runners-up when the margin is small.
    """
    q = (query or "").strip().lower()
    qt = query_tokens(query)
    out: List[Tuple[float, Dict]] = []
    for org in orgs:
        name = str(org.get(name_key) or "")
        short = str(org.get("short_name") or "")
        nl = name.lower()
        s = 0.0
        if nl == q:
            s = 100.0
        elif short and short.lower() == q:
            s = 90.0
        elif q and q in nl:
            s = 60.0 + (10.0 * len(q) / max(len(nl), 1))
        elif q and acronym(name) == re.sub(r"[^a-z0-9]", "", q):
            s = 70.0
        else:
            # Token overlap, then whole-string fuzzy as a last resort.
            nt = tokens(nl)
            if qt and nt:
                overlap = sum(1 for t in qt if t in nt)
                if overlap:
                    s = 20.0 * overlap / len(qt) * (len(nt) and 1.0)
                    # An org whose every word appears in the query is a strong hit
                    # even inside a longer sentence ("ef Example Foundation unifi").
                    if all(t in qt for t in nt):
                        s += 40.0
            if s == 0.0:
                r = SequenceMatcher(None, q, nl).ratio()
                if r >= 0.72:
                    s = 30.0 * r
        if s > 0:
            out.append((s, org))
    out.sort(key=lambda pair: (-pair[0], str(pair[1].get(name_key) or "").lower()))
    return out


def strip_org_terms(query_terms: Sequence[str], org_name: str) -> List[str]:
    """Remove an organization's own words (and its acronym) from a query.

    'ef Example Foundation unified controller' + org 'Example Foundation'
        -> ['unified', 'controller']

    Falls back to the original terms if subtraction would empty the query.
    """
    drop = set(tokens(org_name))
    drop.add(acronym(org_name))
    remaining = [t for t in query_terms if t not in drop]
    return remaining or list(query_terms)
