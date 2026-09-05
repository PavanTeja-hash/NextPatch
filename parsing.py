"""
parsing.py — turn messy human input into a clean list of CVE IDs.

Real users paste CVE lists copied from spreadsheets, scanner reports and emails.
That text is never tidy: extra whitespace, lowercase, duplicates, blank lines,
comma-separated runs, and junk lines with no CVE ID at all (e.g. "weak admin
password on server 3").

We do two things:
  1. Pull out every valid CVE ID, normalise it (UPPERCASE, trimmed) and drop
     duplicates while keeping first-seen order.
  2. Any non-blank line that contains NO CVE ID goes to a separate
     'needs manual review' list — the three databases are all keyed by CVE
     number, so a finding with no CVE simply can't be scored. We surface it
     honestly instead of silently dropping it.
"""

from __future__ import annotations

import re

# CVE-YYYY-NNNN(+) — 4-digit year, then at least 4 digits. Case-insensitive so
# we catch "cve-2021-44228" too.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_input(raw: str):
    """
    Return (cve_ids, needs_review).

      cve_ids      : list[str]  — clean, de-duplicated, UPPERCASE CVE IDs
      needs_review : list[str]  — non-blank input lines that held no CVE ID
    """
    cve_ids: list[str] = []
    seen: set[str] = set()
    needs_review: list[str] = []

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue  # blank line — ignore entirely

        found = CVE_RE.findall(stripped)
        if found:
            for cve in found:
                normalised = cve.upper()
                if normalised not in seen:
                    seen.add(normalised)
                    cve_ids.append(normalised)
        else:
            # a real line with content but no CVE ID -> can't be scored
            needs_review.append(stripped)

    return cve_ids, needs_review


# ===========================================================================
# quick manual test:  python parsing.py
# ===========================================================================

if __name__ == "__main__":
    messy = """  CVE-2021-44228
cve-2021-44228
CVE-2014-0160

  weak admin password on server 3
CVE-2017-0144,CVE-2017-0144
Outdated TLS config, no CVE assigned
CVE-2023-38408 , cve-2020-1472"""

    cves, review = parse_input(messy)

    print("Clean CVE IDs (de-duplicated, uppercased):")
    for c in cves:
        print("  ", c)

    print("\nNeeds manual review (no CVE ID found):")
    for r in review:
        print("  ", r)

    # expectations
    assert cves == [
        "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144",
        "CVE-2023-38408", "CVE-2020-1472",
    ], cves
    assert review == [
        "weak admin password on server 3",
        "Outdated TLS config, no CVE assigned",
    ], review
    print("\nPASS — dirty input cleaned correctly:")
    print("  lowercase normalised, duplicates dropped, blanks ignored,")
    print("  junk lines routed to manual review.")
