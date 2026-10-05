"""Approved-software register.

There is no pre-approved software. Software becomes allowed for EVERYONE when an admin approves a
request for it; a later decision on the same product replaces the earlier one. The register is
read straight from the database (not from RAG), so it is always exact and up to date.
"""
import re

from utils import db

APPROVED = ("Approved", "Approved with Conditions")

# Words too generic to identify a product on their own
_GENERIC = {"software", "client", "player", "media", "personal", "drive", "code", "studio", "visual",
            "microsoft", "google", "adobe", "tool", "tools", "open", "source", "team", "desktop", "app"}


def norm(text):
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def names_match(name, query):
    """True if a product name (e.g. 'Zoom Workplace') is what the query is about
    (e.g. 'Zoom', or 'Can I install zoom?')."""
    n, q = norm(name), norm(query)
    if not n or not q:
        return False
    if n in q or (len(q) >= 3 and q in n):
        return True
    query_words = set(re.findall(r"[a-z0-9+]+", query.lower()))
    return any(w in query_words for w in re.findall(r"[a-z0-9+]+", name.lower())
               if len(w) >= 4 and w not in _GENERIC)


def register():
    """Latest admin decision per product: [{software, status, version, platform, notes, request_id, date}]."""
    latest = {}
    for r in db.list_requests():  # newest first
        if r["status"] == "Pending Review":
            continue
        key = norm(r["software_name"])
        if key and key not in latest:
            latest[key] = {"software": r["software_name"], "status": r["status"],
                           "version": r["requested_version"] or "latest", "platform": r["platform"],
                           "notes": r["reviewer_notes"] or "", "request_id": r["id"],
                           "date": (r["created_at"] or "")[:10]}
    return sorted(latest.values(), key=lambda e: e["software"].lower())


def find(software, exclude_id=None):
    """Register entries for this product (normally 0 or 1)."""
    return [e for e in register() if e["request_id"] != exclude_id and names_match(e["software"], software)]


def is_approved(entry):
    return entry["status"] in APPROVED


def format_register(entries):
    if not entries:
        return "(no software has been approved yet)"
    return "\n".join(
        f"- {e['software']}: {'APPROVED for everyone' if is_approved(e) else 'REJECTED'}"
        f"{' (with conditions)' if e['status'] == 'Approved with Conditions' else ''}"
        f" [Request #{e['request_id']}, {e['date']}, version {e['version']}, {e['platform']}]"
        f"{' - notes: ' + e['notes'] if e['notes'] else ''}" for e in entries)
