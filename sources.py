"""
sources.py — fetch and cache the three data sources NextPatch relies on.

Three sources, three deliberately different caching rules:

  - NVD  : slow + rate-limited, but a CVE's data never changes after publication
           -> cache to disk FOREVER. Only ever fetch a CVE we've never stored.
  - EPSS : fast (all CVEs in one batched request) and updates daily
           -> always fetch fresh. Never cache.
  - KEV  : fast (a single public JSON file) and grows regularly
           -> always fetch fresh. Never cache.

The whole point of NextPatch is that real-world threat data (EPSS, KEV) changes
while the on-paper severity (NVD's CVSS) stays frozen. So we cache the frozen,
slow source and always refresh the live, fast ones.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import requests

# --- paths -----------------------------------------------------------------
CACHE_DIR = Path(__file__).resolve().parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
NVD_CACHE_FILE = CACHE_DIR / "nvd_cache.json"

# --- source URLs -----------------------------------------------------------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD rate limits: 5 requests / 30s without a key, 50 / 30s with one.
# We sleep between requests to stay comfortably under the cap.
NVD_DELAY_NO_KEY = 6.5    # seconds between requests, no API key
NVD_DELAY_WITH_KEY = 0.7  # seconds between requests, with API key

# EPSS: the query string of CVE IDs must stay under 2000 chars; we also cap the
# count per batch so we stay under the API's default page size.
EPSS_MAX_CHARS = 1900
EPSS_MAX_COUNT = 100


# ===========================================================================
# NVD  — permanent on-disk cache
# ===========================================================================

def _load_nvd_cache() -> dict:
    if NVD_CACHE_FILE.exists():
        try:
            return json.loads(NVD_CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_nvd_cache(cache: dict) -> None:
    NVD_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _extract_product(cve: dict) -> str:
    """First readable 'vendor product' from the CPE configuration, if any."""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # cpe:2.3:a:vendor:product:version:...
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    if product and product != "*":
                        return f"{vendor} {product}".strip()
    return ""


def _pick_metric(entries):
    """
    Choose which CVSS entry to trust when NVD returns several.

    NVD often carries both the vendor's own self-assessed CVSS AND NVD's own.
    Vendors have an incentive to under-score their own flaws (Microsoft rated
    Zerologon 5.5/Local; NVD rated it 10.0/Network for the same CVE), so we
    prefer NVD's assessment, then any 'Primary', then whatever's first.
    """
    for e in entries:
        if e.get("source") == "nvd@nist.gov":
            return e
    for e in entries:
        if e.get("type") == "Primary":
            return e
    return entries[0] if entries else None


def _parse_nvd_item(vuln: dict) -> dict:
    """Pull just the fields we need out of one NVD 'vulnerabilities' entry."""
    cve = vuln.get("cve", {})

    # description (prefer English)
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS base score + attack vector — try v3.1, then v3.0, then v2.
    # The attack vector tells us HOW a flaw is reached: NETWORK (remotely, over
    # the internet), ADJACENT_NETWORK (same local network), LOCAL (needs local
    # access first) or PHYSICAL. v3 calls it 'attackVector'; v2 'accessVector'.
    # NextPatch uses this so the 'internet-facing' multiplier only boosts flaws
    # an internet attacker can actually reach.
    cvss = None
    attack_vector = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            try:
                data = _pick_metric(entries)["cvssData"]
                cvss = float(data["baseScore"])
                attack_vector = data.get("attackVector") or data.get("accessVector")
                break
            except (KeyError, IndexError, TypeError, ValueError):
                continue

    return {
        "id": cve.get("id", ""),
        "description": description,
        "cvss": cvss,
        "attack_vector": attack_vector,
        "product": _extract_product(cve),
    }


def fetch_nvd(cve_ids, api_key=None, progress=None) -> dict:
    """
    Return {cve_id: {id, description, cvss, product}} for every requested CVE.

    Reads from the on-disk cache first; only hits the network for CVE IDs we
    have never stored. Newly fetched items are written back to the cache.

    `progress`, if given, is called as progress(done, total, cve_id) so a UI
    can show a progress bar during the (slow) NVD fetch.
    """
    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY")

    cache = _load_nvd_cache()
    to_fetch = [c for c in cve_ids if c not in cache]

    headers = {"apiKey": api_key} if api_key else {}
    delay = NVD_DELAY_WITH_KEY if api_key else NVD_DELAY_NO_KEY

    for i, cve in enumerate(to_fetch):
        if progress:
            progress(i + 1, len(to_fetch), cve)
        try:
            resp = requests.get(
                NVD_URL, params={"cveId": cve}, headers=headers, timeout=30
            )
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                if vulns:
                    cache[cve] = _parse_nvd_item(vulns[0])
                else:
                    # a real NVD response with no match -> the CVE ID doesn't
                    # exist. Safe to cache; it won't start existing later.
                    cache[cve] = {
                        "id": cve, "description": "", "cvss": None,
                        "attack_vector": None, "product": "", "not_found": True,
                    }
            # any non-200 (rate limit, server error): do NOT cache, so we can
            # retry on a later run.
        except requests.RequestException:
            pass  # network hiccup — leave it uncached for a retry

        # be polite to the rate limiter (no need to wait after the last one)
        if i < len(to_fetch) - 1:
            time.sleep(delay)

    if to_fetch:
        _save_nvd_cache(cache)

    return {
        cve: cache.get(
            cve, {"id": cve, "description": "", "cvss": None,
                  "attack_vector": None, "product": ""}
        )
        for cve in cve_ids
    }


# ===========================================================================
# EPSS  — always fresh, batched
# ===========================================================================

def _batch_cves(cve_ids, max_chars=EPSS_MAX_CHARS, max_count=EPSS_MAX_COUNT):
    """Group CVE IDs into comma-joined batches under both length and count caps."""
    batches, current, length = [], [], 0
    for cve in cve_ids:
        addition = len(cve) + (1 if current else 0)  # +1 for the joining comma
        too_long = length + addition > max_chars
        too_many = len(current) >= max_count
        if current and (too_long or too_many):
            batches.append(current)
            current, length = [], 0
            addition = len(cve)
        current.append(cve)
        length += addition
    if current:
        batches.append(current)
    return batches


def fetch_epss(cve_ids) -> dict:
    """
    Return {cve_id: probability_float} for CVEs that EPSS has data on.

    A CVE that EPSS has never scored is simply ABSENT from the result — the
    caller must treat "missing" as 'No data', never as a probability of 0.
    """
    result = {}
    for batch in _batch_cves(list(cve_ids)):
        try:
            resp = requests.get(
                EPSS_URL, params={"cve": ",".join(batch)}, timeout=30
            )
            if resp.status_code == 200:
                for row in resp.json().get("data", []):
                    try:
                        result[row["cve"]] = float(row["epss"])
                    except (KeyError, ValueError, TypeError):
                        continue
        except requests.RequestException:
            pass
    return result


# ===========================================================================
# KEV  — always fresh, one file
# ===========================================================================

def fetch_kev() -> set:
    """
    Return a set of CVE IDs that CISA confirms are under active exploitation.

    Downloads the whole KEV feed once; membership is then a local set lookup.
    On any network error we return an empty set (the app still runs; every CVE
    just shows as 'not confirmed on KEV').
    """
    try:
        resp = requests.get(KEV_URL, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return {
                v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v
            }
    except requests.RequestException:
        pass
    return set()


# ===========================================================================
# quick manual test:  python sources.py
# ===========================================================================

if __name__ == "__main__":
    sample = [
        "CVE-2021-44228",  # Log4Shell — on KEV, very high EPSS
        "CVE-2014-0160",   # Heartbleed
        "CVE-2017-0144",   # EternalBlue — on KEV
        "CVE-2023-38408",  # a normal one
    ]

    print("Fetching KEV feed (one file)...")
    kev = fetch_kev()
    print(f"  KEV entries loaded: {len(kev)}")

    print("\nFetching EPSS (one batched request)...")
    epss = fetch_epss(sample)
    print(f"  EPSS scores returned: {len(epss)}")

    print("\nFetching NVD (cached; only uncached CVEs hit the network)...")
    nvd = fetch_nvd(sample)

    print("\n{:<18} {:>6} {:>9}  {:<8} {}".format(
        "CVE", "CVSS", "EPSS", "ON KEV?", "DESCRIPTION"))
    print("-" * 90)
    for cve in sample:
        info = nvd[cve]
        cvss = info["cvss"]
        prob = epss.get(cve)
        print("{:<18} {:>6} {:>9}  {:<8} {}".format(
            cve,
            "-" if cvss is None else f"{cvss:.1f}",
            "No data" if prob is None else f"{prob*100:.2f}%",
            "YES" if cve in kev else "no",
            (info["description"][:52] + "...") if info["description"] else "(none)",
        ))
