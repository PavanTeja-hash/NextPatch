"""
ai.py — OPTIONAL Google Gemini layer. It EXPLAINS and WRITES; it never RANKS.

Why the AI is kept away from the ranking: if a client asks "why is this third?",
the answer must be arithmetic we can show them (see scoring.py), not "the model
decided." A model can't be audited, and in security work an unexplainable
priority list is unusable. So Gemini only turns numbers/jargon into readable
English — the order on screen is always the plain math.

The whole app must work with NO Gemini key. If the key or library is missing,
is_available() returns False and the UI hides these features. Fetching, scoring
and ranking are completely unaffected.

Responses are cached to cache/ai_cache.json so a demo doesn't re-generate the
same text and burn quota.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent / "cache"
CACHE_DIR.mkdir(exist_ok=True)
AI_CACHE_FILE = CACHE_DIR / "ai_cache.json"

# Model is configurable; a fast, cheap model is plenty for short explanations.
# 'gemini-flash-latest' is an alias that tracks the current fast model, so it
# keeps working as Google rotates versions. Override with the GEMINI_MODEL env var.
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")

_client = None  # lazily created on first use


# --- availability ----------------------------------------------------------

def _api_key():
    return os.environ.get("GEMINI_API_KEY")


def availability_reason() -> str:
    """'ok' if the AI layer is usable, otherwise a one-line reason it isn't."""
    if not _api_key():
        return "no GEMINI_API_KEY found (check the host's env vars / Secrets)"
    try:
        from google import genai  # noqa: F401
    except Exception as exc:
        return f"google-genai import failed: {exc}"
    return "ok"


def is_available() -> bool:
    """True only if BOTH the key is set AND the library imports."""
    return availability_reason() == "ok"


def _get_client():
    """The google-genai client (the maintained SDK; google-generativeai is EOL)."""
    global _client
    if _client is None:
        from google import genai
        _client = genai.Client(api_key=_api_key())
    return _client


def _generate(prompt: str) -> str:
    """One prompt in, plain text out."""
    resp = _get_client().models.generate_content(
        model=MODEL_NAME, contents=prompt
    )
    return resp.text or ""


# --- disk cache ------------------------------------------------------------

def _load_cache() -> dict:
    if AI_CACHE_FILE.exists():
        try:
            return json.loads(AI_CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    AI_CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def _cached(key: str, generate) -> str:
    """Return cached text for `key`, else call generate(), cache it, return it."""
    cache = _load_cache()
    if key in cache:
        return cache[key]
    try:
        text = generate().strip()
    except Exception as exc:  # network/quota/model error — never crash the app
        return f"(AI unavailable right now: {exc})"
    cache[key] = text
    _save_cache(cache)
    return text


# --- feature 1: plain-English translation (keyed by CVE ID) ----------------

def plain_english(cve_id: str, description: str) -> str:
    """Two plain sentences: what this actually lets an attacker do."""
    def generate():
        prompt = (
            "You are explaining a software security flaw to a non-technical IT "
            "manager. In EXACTLY two short sentences, in plain English with no "
            "jargon, say what an attacker could actually DO if they exploited it. "
            "Do not repeat the CVE ID or restate the raw description. "
            f"Technical description:\n{description}"
        )
        return _generate(prompt)
    return _cached(f"plain::{cve_id}", generate)


# --- feature 2: remediation write-up for the top items ---------------------

def _context_sig(context: dict) -> str:
    return "".join(k[0] for k in ("internet", "sensitive", "test") if context.get(k)) or "none"


def remediation_writeup(scored: dict, context: dict) -> str:
    """
    A short paragraph a pen-tester could paste into a report: what it is, why
    it's urgent on THIS machine given the asset context, and what to do.

    Cached per (CVE, asset-context) because the text references the context.
    The AI is told the numbers as FACTS — it must not re-rank or invent data.
    """
    cve = scored["cve"]
    key = f"remediation::{cve}::{_context_sig(context)}"

    ctx_bits = [lbl for lbl, on in [
        ("reachable from the internet", context.get("internet")),
        ("holds sensitive data", context.get("sensitive")),
        ("a throwaway test machine", context.get("test")),
    ] if on]
    ctx_text = ", ".join(ctx_bits) if ctx_bits else "no special context set"

    kev_text = ("It is on CISA's Known Exploited Vulnerabilities list — attackers "
                "are confirmed to be using it right now."
                if scored["on_kev"] else
                "It is not on CISA's confirmed-exploited list.")
    epss_text = ("no public exploitation-probability data"
                 if scored["epss"] is None
                 else f"an exploitation probability of about {scored['epss']*100:.1f}% "
                      "in the next 30 days (EPSS)")

    def generate():
        prompt = (
            "Write a short, calm remediation note (3-4 sentences) for a security "
            "report, aimed at an IT manager. Use ONLY the facts given; do not "
            "invent version numbers, dates, or exploitation claims, and do not "
            "argue about the priority order.\n\n"
            f"Flaw: {cve}\n"
            f"What it is: {scored.get('description', '(no description)')}\n"
            f"On-paper severity (CVSS): {scored.get('cvss')}\n"
            f"Real-world threat: {kev_text} It has {epss_text}.\n"
            f"This machine is: {ctx_text}.\n"
            f"NextPatch priority score: {scored['final_score']:.2f} "
            f"(threat state: {scored['state']}).\n\n"
            "Cover: (1) what it is in one plain sentence, (2) why it matters on "
            "THIS machine given the context above, (3) the practical next step "
            "(patch / upgrade / isolate). No headings, just the paragraph."
        )
        return _generate(prompt)
    return _cached(key, generate)


# ===========================================================================
# quick manual test:  python ai.py
# ===========================================================================

if __name__ == "__main__":
    print("AI available:", is_available())
    if is_available():
        print(f"Model: {MODEL_NAME}\n")
        desc = ("Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in "
                "configuration, log messages, and parameters do not protect "
                "against attacker controlled LDAP and other JNDI related endpoints.")
        print("Plain English (CVE-2021-44228):")
        print(" ", plain_english("CVE-2021-44228", desc))

        demo = {
            "cve": "CVE-2021-44228", "cvss": 10.0, "epss": 0.944, "on_kev": True,
            "final_score": 22.9, "state": "Confirmed", "description": desc,
        }
        print("\nRemediation write-up (internet-facing + sensitive):")
        print(" ", remediation_writeup(demo, {"internet": True, "sensitive": True, "test": False}))
