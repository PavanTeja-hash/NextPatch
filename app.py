"""
app.py — NextPatch: which vulnerabilities should you actually patch first?

A scan finds 400 flaws. You can fix 20 this month. NextPatch ranks them by
combining on-paper severity (CVSS) with real-world threat (is anyone actually
attacking this?) and the context of the machine it lives on.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

import sources
import scoring
from parsing import parse_input


def _bridge_secrets_to_env():
    """
    Let the app read its keys on any host.

    The framework-agnostic modules (sources.py, ai.py) read keys from
    environment variables. When deployed to Streamlit Community Cloud, secrets
    are set in the dashboard and surfaced via st.secrets — so we copy them into
    os.environ here. Locally, real env vars just win. Never commit real keys.
    """
    try:
        for key in ("GEMINI_API_KEY", "NVD_API_KEY", "GEMINI_MODEL"):
            if key not in os.environ and key in st.secrets:
                os.environ[key] = str(st.secrets[key])
    except Exception:
        pass  # no secrets.toml present (e.g. plain local run) — that's fine


_bridge_secrets_to_env()

# AI layer is optional and built last. Import defensively so the core tool
# never breaks if it's absent or its key is missing.
try:
    import ai
    AI_IMPORTED = True
except Exception:
    AI_IMPORTED = False

DEMO_FILE = Path(__file__).resolve().parent / "cache" / "demo_cves.json"

st.set_page_config(page_title="NextPatch", page_icon="🩹", layout="wide")


# ===========================================================================
# data loading  (fetch on demand, then keep in session so toggling the asset
# context only RE-SCORES — it never re-fetches)
# ===========================================================================

@st.cache_data(show_spinner=False, ttl=3600)
def load_kev():
    """KEV feed — fetched fresh, cached only for this session (one file)."""
    return sources.fetch_kev()


@st.cache_data(show_spinner=False, ttl=3600)
def load_epss(cve_tuple):
    """EPSS — fetched fresh, cached for the session, batched in one request."""
    return sources.fetch_epss(list(cve_tuple))


def load_records(cve_ids):
    """
    Fetch NVD (cached to disk) + EPSS (fresh) + KEV (fresh) and assemble the
    raw per-CVE records that scoring needs. Shows a progress bar for the slow
    NVD step (only uncached CVEs actually hit the network).
    """
    kev = load_kev()
    epss = load_epss(tuple(cve_ids))

    # NVD — the slow one. Progress bar covers only genuinely-uncached CVEs.
    progress_box = st.empty()
    bar = st.progress(0.0)

    def on_progress(done, total, cve):
        progress_box.write(f"Fetching NVD data… {done}/{total}  ({cve})")
        bar.progress(done / total if total else 1.0)

    nvd = sources.fetch_nvd(cve_ids, progress=on_progress)
    bar.empty()
    progress_box.empty()

    records = []
    for cve in cve_ids:
        info = nvd.get(cve, {})
        records.append({
            "cve": cve,
            "cvss": info.get("cvss"),
            "epss": epss.get(cve),        # None if EPSS has no data — never faked
            "on_kev": cve in kev,
            "attack_vector": info.get("attack_vector"),
            "description": info.get("description", ""),
            "product": info.get("product", ""),
        })
    return records


# ===========================================================================
# reversal detection — the "money shot": a lower-CVSS flaw ranked above a
# higher-CVSS one, because the lower one is actually under attack.
# ===========================================================================

def _is_dormant(s, epss_cap=0.10):
    """A 'scary on paper, nobody attacking it' flaw: not on KEV and low EPSS.

    These are exactly the flaws that a CVSS-only sort ranks too high. A flaw
    with high EPSS but no KEV is NOT dormant — it's genuinely likely to be
    attacked — so it doesn't count as a reversal victim.
    """
    return (not s["on_kev"]) and (s["epss"] is None or s["epss"] < epss_cap)


def mark_reversals(scored, min_gap=2.0):
    """
    Flag rows that outrank a clearly-scarier-BUT-DORMANT flaw — the real
    'money shot'. Row i is flagged if some lower-ranked flaw j has a CVSS at
    least `min_gap` higher yet is dormant (see _is_dormant). The gap is set high
    enough that only striking reversals (e.g. a CVSS 7 flaw above a CVSS 9.8 one)
    are highlighted, not every minor inversion.
    """
    flags = {}
    for i, s in enumerate(scored):
        if s["cvss"] is None:
            flags[i] = False
            continue
        flagged = False
        for j in range(i + 1, len(scored)):
            low = scored[j]
            if (low["cvss"] is not None and _is_dormant(low)
                    and low["cvss"] - s["cvss"] >= min_gap):
                flagged = True
                break
        flags[i] = flagged
    return flags


def biggest_reversal(scored, flags):
    """The single most striking reversal (biggest CVSS gap) for the callout."""
    best = None
    for i, s in enumerate(scored):
        if not flags.get(i) or s["cvss"] is None:
            continue
        for j in range(i + 1, len(scored)):
            low = scored[j]
            if (low["cvss"] is not None and _is_dormant(low)
                    and low["cvss"] > s["cvss"]):
                gap = low["cvss"] - s["cvss"]
                if best is None or gap > best["gap"]:
                    best = {"high": s, "high_rank": i + 1,
                            "low": low, "low_rank": j + 1, "gap": gap}
    return best


# ===========================================================================
# display helpers
# ===========================================================================

def fmt_epss(p):
    return "No data" if p is None else f"{p * 100:.2f}%"


def fmt_cvss(c):
    return None if c is None else round(c, 1)


def fmt_vector(av):
    """Short label for the CVSS attack vector (how the flaw is reached)."""
    return {
        "NETWORK": "Network",
        "ADJACENT_NETWORK": "Adjacent",
        "LOCAL": "Local",
        "PHYSICAL": "Physical",
    }.get(av, "—")


def build_display_df(scored, flags):
    rows = []
    for i, s in enumerate(scored):
        rows.append({
            "Rank": i + 1,
            "CVE": s["cve"],
            "Final": round(s["final_score"], 2),
            "CVSS": fmt_cvss(s["cvss"]),
            "Vector": fmt_vector(s.get("attack_vector")),
            "EPSS": fmt_epss(s["epss"]),
            "KEV": "✔ Confirmed" if s["on_kev"] else "—",
            "State": s["state"],
            "Flag": "⬆ Low CVSS, high priority" if flags.get(i) else "",
            "Description": (s["description"][:90] + "…") if s.get("description") else "",
        })
    return pd.DataFrame(rows)


def style_df(df, flags):
    """Colour the Final cell by severity bucket; tint reversal rows."""
    def final_cell(val):
        try:
            s = float(val)
        except (TypeError, ValueError):
            return ""
        if s >= 9:
            bg, fg = "#c0392b", "white"
        elif s >= 6:
            bg, fg = "#e67e22", "white"
        elif s >= 3:
            bg, fg = "#f1c40f", "#111"
        else:
            bg, fg = "#95a5a6", "#111"
        return f"background-color: {bg}; color: {fg}; font-weight: 700;"

    def reversal_row(row):
        return ["background-color: #fff3cd" if flags.get(row.name) else ""] * len(row)

    return (df.style
              .apply(reversal_row, axis=1)
              .map(final_cell, subset=["Final"])
              .format({"Final": "{:.2f}",
                       "CVSS": lambda v: "—" if pd.isna(v) else f"{v:.1f}"}))


def build_csv(scored):
    """Full-precision export the user can hand to auditors."""
    rows = []
    for i, s in enumerate(scored):
        rows.append({
            "rank": i + 1,
            "cve": s["cve"],
            "final_score": round(s["final_score"], 3),
            "cvss": s["cvss"],
            "attack_vector": s.get("attack_vector"),
            "epss_probability": s["epss"],
            "on_kev": s["on_kev"],
            "threat_score": s["threat"],
            "impact_score": s["impact"],
            "base_score": round(s["base"], 3),
            "internet_boost_applied": s.get("internet_applied"),
            "threat_state": s["state"],
            "description": s.get("description", ""),
        })
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")


def render_breakdown(s, ai_on):
    """Show the full arithmetic chain for one scored CVE — every number visible."""
    # threat
    if s["threat"] is None:
        st.markdown("**Step 1 · Threat (0–10):** `Unknown` — no KEV, no EPSS data. "
                    "We do **not** call this 0 or 'safe'; nobody has seen it "
                    "exploited *yet*.")
        threat_num = 0.0
    else:
        st.markdown(f"**Step 1 · Threat (0–10):** `{s['threat']:.2f}`  — {s['threat_source']}")
        threat_num = s["threat"]

    # impact
    if s["cvss"] is None:
        st.markdown("**Step 2 · Impact (0–10):** `No CVSS` from NVD.")
    else:
        st.markdown(f"**Step 2 · Impact (0–10):** `{s['cvss']:.1f}`  — the CVSS base score")

    # base
    st.markdown(
        f"**Step 3 · Base:** "
        f"(threat {threat_num:.2f} × 0.6) + (impact {(s['cvss'] or 0):.1f} × 0.4) "
        f"= (`{s['threat_component']:.2f}`) + (`{s['impact_component']:.2f}`) "
        f"= **`{s['base']:.2f}`**"
    )

    # multipliers
    if s["multipliers"]:
        chain = " × ".join(f"{factor} ({lbl})" for lbl, factor in s["multipliers"])
        st.markdown(f"**Step 4 · Asset multipliers:** base × {chain}")
    else:
        st.markdown("**Step 4 · Asset multipliers:** none applied (× 1.0)")

    # explain the attack-vector gate on the internet multiplier
    av = s.get("attack_vector") or "unknown"
    if s.get("internet_requested") and not s.get("internet_applied"):
        st.caption(f"↳ Internet-facing ×1.5 was **not** applied: this flaw's attack "
                   f"vector is **{av}**, so it isn't reachable straight from the "
                   f"internet — exposure doesn't make it easier to exploit.")
    elif s.get("internet_applied"):
        st.caption(f"↳ Internet-facing ×1.5 applied: attack vector is **{av}** "
                   f"(reachable over the network).")

    st.markdown(f"**Final score = `{s['final_score']:.2f}`**")

    if s.get("description"):
        st.caption("NVD description: " + s["description"])

    # AI plain-English translation (optional)
    if AI_IMPORTED and ai_on and s.get("description"):
        if st.button(f"Explain {s['cve']} in plain English", key=f"ai_{s['cve']}"):
            with st.spinner("Asking Gemini…"):
                st.info(ai.plain_english(s["cve"], s["description"]))


# ===========================================================================
# SIDEBAR — input mode + asset context
# ===========================================================================

PRESETS = {
    "Custom": None,
    "Public Web Server": {"internet": True, "sensitive": True, "test": False},
    "Internal Test Lab": {"internet": False, "sensitive": False, "test": True},
}

# initialise checkbox state once
for key in ("internet", "sensitive", "test"):
    st.session_state.setdefault(key, False)


def apply_preset():
    """When the preset dropdown changes, PRE-FILL the checkboxes.

    The preset is only a starting point: it writes values into the boxes but
    does not lock them. The user can untick any box afterwards and that change
    sticks, because the checkboxes own their own session_state.
    """
    values = PRESETS.get(st.session_state.preset)
    if values is not None:  # 'Custom' leaves whatever is already ticked
        for key, val in values.items():
            st.session_state[key] = val


with st.sidebar:
    st.header("1 · Input")
    mode = st.radio(
        "Where do the CVEs come from?",
        ["Load example (demo)", "Enter my own"],
        help="The demo loads ~30 pre-selected flaws with NVD data already cached "
             "to disk, so it opens instantly.",
    )

    st.divider()
    st.header("2 · Asset context")
    st.caption("Where does this machine live? This only *re-scores* — it never "
               "re-fetches, so switching presets instantly reorders the list.")

    st.selectbox("Preset (a shortcut — boxes stay editable)",
                 list(PRESETS), key="preset", on_change=apply_preset)

    st.checkbox("Reachable from the internet  (× 1.5)", key="internet")
    st.checkbox("Holds sensitive data  (× 1.3)", key="sensitive")
    st.checkbox("Throwaway test machine  (× 0.5)", key="test")

    st.divider()
    st.caption(
        "**Weights are configurable.** The 0.6 / 0.4 split and the ×1.5 / ×1.3 / "
        "×0.5 multipliers are a starting judgement, not science — you'd tune them "
        "with your security team. They are not authoritative."
    )

    if AI_IMPORTED:
        ai_on = ai.is_available()
        if ai_on:
            st.success("AI explanations: ON (Gemini key found)")
        else:
            st.info("AI explanations: OFF — set GEMINI_API_KEY to enable. "
                    "The tool works fully without it.")
    else:
        ai_on = False

context = {
    "internet": st.session_state.internet,
    "sensitive": st.session_state.sensitive,
    "test": st.session_state.test,
}


# ===========================================================================
# MAIN — title + input
# ===========================================================================

st.title("🩹 NextPatch")
st.markdown(
    "**A scan finds 400 flaws. You can fix 20 this month. Which 20?**  \n"
    "CVSS tells you how bad a flaw is *if* attacked. It doesn't tell you whether "
    "anyone *is* attacking it. NextPatch adds real-world threat data (EPSS + CISA "
    "KEV) and your machine's context, then ranks by what will actually get you breached."
)

cve_ids: list[str] = []
needs_review: list[str] = []

if mode == "Load example (demo)":
    if DEMO_FILE.exists():
        demo = json.loads(DEMO_FILE.read_text(encoding="utf-8"))
        demo_ids = demo.get("cve_ids", [])
        st.info(f"Demo list: **{len(demo_ids)}** hand-picked flaws chosen to show "
                "the reversal — famous bugs, scary-but-dormant flaws, and "
                "moderate-looking flaws that are under active attack.")
        if st.button("▶  Load example", type="primary"):
            st.session_state.run = True
            st.session_state.cve_ids = demo_ids
            st.session_state.needs_review = []
    else:
        st.warning("Demo data not built yet (cache/demo_cves.json missing).")
else:
    st.write("Paste CVE IDs (one per line or comma-separated). Messy input is fine — "
             "extra spaces, lowercase, duplicates and blank lines are handled, and "
             "lines with no CVE ID go to a separate *Needs manual review* list.")
    pasted = st.text_area("CVE IDs", height=160,
                          placeholder="CVE-2021-44228\ncve-2017-0144\nweak admin password on server 3")
    uploaded = st.file_uploader("…or upload a CSV / text file", type=["csv", "txt"])

    if st.button("▶  Score these CVEs", type="primary"):
        raw = pasted or ""
        if uploaded is not None:
            raw += "\n" + uploaded.getvalue().decode("utf-8", errors="ignore")
        ids, review = parse_input(raw)
        st.session_state.run = True
        st.session_state.cve_ids = ids
        st.session_state.needs_review = review


# ===========================================================================
# MAIN — results
# ===========================================================================

if st.session_state.get("run"):
    cve_ids = st.session_state.get("cve_ids", [])
    needs_review = st.session_state.get("needs_review", [])

    if not cve_ids and not needs_review:
        st.warning("No CVE IDs found in your input.")
        st.stop()

    if cve_ids:
        records = load_records(cve_ids)
        scored = scoring.score_all(records, context)
        flags = mark_reversals(scored)

        # --- summary metrics ---
        confirmed = sum(1 for s in scored if s["on_kev"])
        unknown = sum(1 for s in scored if s["state"] == scoring.STATE_UNKNOWN)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Flaws scored", len(scored))
        c2.metric("Confirmed under attack (KEV)", confirmed)
        c3.metric("Unknown threat state", unknown)
        c4.metric("Reversals flagged", sum(flags.values()))

        # --- the money-shot callout ---
        rev = biggest_reversal(scored, flags)
        if rev:
            st.error(
                f"**The reversal — this is the whole point.**  \n"
                f"**{rev['high']['cve']}** (CVSS **{rev['high']['cvss']:.1f}**, "
                f"*{rev['high']['state']}*) is ranked **#{rev['high_rank']}**, "
                f"*above* **{rev['low']['cve']}** (CVSS **{rev['low']['cvss']:.1f}**) "
                f"sitting at **#{rev['low_rank']}**.  \n"
                f"The lower-CVSS flaw wins because it's actually being exploited, "
                f"while the scarier-looking one isn't. Sorting by CVSS alone would "
                f"put the wrong flaw first."
            )

        # --- context echo ---
        active = [lbl for lbl, on in
                  [("internet-facing ×1.5", context["internet"]),
                   ("sensitive data ×1.3", context["sensitive"]),
                   ("test machine ×0.5", context["test"])] if on]
        st.caption("Asset context applied: " + (", ".join(active) if active else "none"))

        # --- results table ---
        st.subheader("Ranked by what to patch first")
        df = build_display_df(scored, flags)
        st.dataframe(style_df(df, flags), use_container_width=True, hide_index=True,
                     height=min(560, 60 + 35 * len(df)))
        st.caption("🟥 fix first · 🟧 high · 🟨 medium · ⬜ low  ·  "
                   "highlighted rows outrank a scarier-looking CVSS flaw.")

        st.download_button("⬇  Download full report (CSV)", data=build_csv(scored),
                           file_name="nextpatch_report.csv", mime="text/csv")

        # --- AI remediation for the top 10 (only if enabled) ---
        if AI_IMPORTED and ai_on:
            st.subheader("AI remediation write-ups (top 10)")
            st.caption("The AI only *explains* — it never changes the ranking above.")
            if st.button("Generate write-ups for the top 10"):
                for s in scored[:10]:
                    with st.spinner(f"Writing up {s['cve']}…"):
                        text = ai.remediation_writeup(s, context)
                    with st.expander(f"{s['cve']} — final {s['final_score']:.2f}"):
                        st.write(text)

        # --- per-CVE breakdown (step 5): every number, nothing hidden ---
        st.subheader("🔍 Score breakdown — every number, nothing hidden")
        st.caption("Open any flaw to see exactly how its score was built. This is "
                   "why the ranking is auditable: it's arithmetic, not a model.")
        for i, s in enumerate(scored):
            title = f"#{i+1}  ·  {s['cve']}  ·  final {s['final_score']:.2f}"
            if flags.get(i):
                title += "   ⬆ outranks a scarier CVSS"
            with st.expander(title):
                render_breakdown(s, ai_on)

        # --- needs manual review ---
    if needs_review:
        st.subheader("⚠ Needs manual review")
        st.caption("These lines had no CVE ID, so the CVE-keyed databases can't "
                   "score them. The tool only ranks what it can actually measure.")
        st.table(pd.DataFrame({"Input with no CVE ID": needs_review}))
