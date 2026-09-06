# 🩹 NextPatch

**A vulnerability scan finds 400 flaws. Your team can fix 20 this month. Which 20?**

NextPatch ranks a list of known software vulnerabilities (CVEs) by how urgent they
actually are - not by how scary they look on paper. It combines the on-paper
severity of each flaw with **real-world threat data** (is anyone actually
attacking it?) and the **context of the machine** it lives on, then produces a
transparent, auditable "patch this first" list.

---

## The problem

Every known software flaw gets a public ID - a **CVE** (e.g. `CVE-2021-44228`) -
and a severity score out of 10 called **CVSS**. Roughly half of all CVEs score 7+.
So a scan of a real network returns hundreds of "critical" findings, and a small
IT team can't fix them all at once.

The usual fix is to sort by CVSS and work down the list. **That sorts by the wrong
thing.** CVSS measures how bad a flaw would be *if* someone attacked it. It says
nothing about whether anyone *is*. Most high-CVSS flaws are never exploited by
anyone; meanwhile some medium-CVSS flaw is being used by criminals worldwide
today. CVSS is also assigned by a human (often the vendor, who has an incentive to
score their own flaws low), so the same CVE can carry different scores in different
places.

NextPatch fixes the sort by folding in evidence of real-world exploitation.

---

## The three data sources

| Source | Question it answers | What we take | Caching |
|--------|--------------------|--------------|---------|
| **NVD** (US NIST) | How bad is it *if* used? | description, CVSS base score, attack vector | **cache forever** |
| **EPSS** (FIRST.org) | How *likely* is anyone to attack it worldwide in 30 days? | probability 0-1 | always fresh |
| **CISA KEV** | Is someone *confirmed* attacking it now? | yes / no | always fresh |

The trust ladder: **KEV** (confirmed fact) > **EPSS** (prediction) > **CVSS**
(opinion on paper).

### The caching decision (deliberate)

- **NVD → cached permanently to disk.** A CVE's description and CVSS almost never
  change after publication, and NVD is the slow, rate-limited source. Once we've
  fetched a CVE we never fetch it again.
- **EPSS and KEV → always fetched fresh.** They change daily/regularly, and
  they're fast (EPSS takes every CVE in one batched request; KEV is a single
  file).

This is the whole thesis in miniature: **real-world threat changes while paper
severity stays frozen.** Caching the threat data would turn the tool into a
one-day snapshot and collapse the argument. So we cache the frozen-but-slow source
and always refresh the live-but-fast ones.

---

## The scoring model - plain arithmetic, no AI

Every number in the ranking is explainable, because clients have to justify their
patching order to auditors. No machine learning is involved in the score.

**1. Threat (0-10) - is anyone attacking this?**
- On KEV → `10` (a confirmed fact beats any prediction)
- else, has EPSS → `EPSS × 10`
- else → `Unknown` (see *Honest handling of missing data*)

**2. Impact (0-10) - how bad if it works?**
- `impact = CVSS base score`

**3. Base**
- `base = (threat × 0.6) + (impact × 0.4)`
- Threat is weighted heavier on purpose: a flaw nobody attacks can't hurt you,
  however severe it looks.

**4. Asset-context** (only the operator knows these)
- Reachable from the internet → `× 1.5` - **but only for network-exploitable
  flaws** (see below)
- Holds sensitive data → `× 1.3`
- `final = base × (every applicable multiplier)`

**5. Throwaway test machine → a cap, not a multiplier**
- The score is clamped to `5.0`, and the two boosts above are **skipped**.
- Why not a multiplier: multipliers compose, so `1.5 × 1.3 × 0.5 = 0.975`, which
  meant a disposable box cancelled almost exactly back to full priority. A
  ceiling can't be defeated by any combination of ticks.
- Dropping the `0.5` but keeping the boosts would be worse still: a low-severity
  flaw on a test box would score `base × 1.95`, i.e. *higher* than on an
  unflagged machine. So a test box is scored on its base risk alone, then capped.

### Attack-vector-aware internet multiplier

CVSS records each flaw's **attack vector** - whether it's reachable *remotely over
the network* or only by someone *already on the machine* (local). A local
privilege-escalation flaw isn't any easier to exploit just because the box faces
the internet; the attacker still has to get onto the box first. So the
internet-facing ×1.5 is applied **only to network-exploitable flaws**. This is
both more accurate and the reason switching asset presets visibly **re-orders**
the list (network flaws rise on an internet-facing host; local flaws don't).

### The reversal (the whole point)

| | Flaw A | Flaw B |
|---|---|---|
| CVSS | **9.8** | 6.5 |
| On KEV? | No | **Yes** |
| EPSS | 0.005 | - |
| Threat | 0.05 | 10 |
| Base | 3.95 | 8.6 |
| Internet-facing | No | Yes (network) → ×1.5 |
| **FINAL** | **3.95** | **12.9** |

Flaw A looks far scarier by CVSS. Flaw B is the one that actually gets you
breached. Sorting by CVSS alone puts the wrong flaw first.

### A note on the weights

`0.6, 0.4, 1.5, 1.3` and the `5.0` test-machine cap are a starting judgement,
**not science**. They're surfaced as configurable in the UI and would be tuned
with a real security team. They are not presented as authoritative.

---

## Honest handling of missing data

The tool never fakes data or claims safety it can't support:

- **Not in EPSS →** shown as *No data*, never treated as 0. Absence of data is not
  evidence of safety.
- **Not on KEV →** normal and expected (KEV has only a few thousand of the
  hundreds of thousands of CVEs), not an error.
- **Neither KEV nor meaningful EPSS →** labelled **Unknown**, not *Safe*. It means
  nobody has seen it exploited *yet*. Most tools quietly rank these last, which is
  a claim they can't back up; NextPatch shows the state explicitly.
- **Input line with no CVE ID** (a config mistake, a weak password) → the three
  databases are all keyed by CVE, so it can't be scored. It goes to a separate
  **Needs manual review** list rather than being silently dropped.

---

## The AI layer (optional) - it explains, it never ranks

Google Gemini is used only to **translate and write**, never to decide the order:

1. **Plain-English translation** - turns an engineer-facing CVE description into
   two sentences a non-technical manager understands.
2. **Remediation write-ups** - for the top items, a short paragraph: what it is,
   why it's urgent *on this machine given its context*, and what to do.

The ranking is always the plain arithmetic above. If a client asks "why is this
third?", the answer must be math we can show them, not "the model decided" - a
model can't be audited, and an unexplainable priority list is unusable in security
work.

**The tool works fully without an AI key.** If `GEMINI_API_KEY` is unset (or the
library is missing), the AI features are hidden and everything else - fetching,
scoring, ranking - is unaffected. AI responses are cached to disk so a demo
doesn't re-generate the same text and burn quota.

---

## What's original here (and what isn't)

Combining KEV, EPSS and NVD to prioritise vulnerabilities is **established
practice** in vulnerability management - this project doesn't claim to invent it.
What this particular implementation adds on top:

- an **asset-context layer** (the machine's exposure and sensitivity), including
  the attack-vector-aware internet multiplier;
- an explicit **"Unknown"** threat state instead of silently ranking
  never-seen-exploited flaws last;
- an **AI explanation layer** that is deliberately kept out of the ranking.

There are no benchmarks or accuracy claims in this project because it makes none -
it's a prioritisation aid whose every number is meant to be inspected, not a
predictor to be scored.

---

## Running it

```bash
pip install -r requirements.txt
streamlit run app.py
```

**Two input modes:**
- **Load example (demo)** - ~30 hand-picked CVEs with NVD data pre-cached to disk,
  so it opens instantly (even offline for the NVD part). EPSS and KEV are still
  fetched fresh.
- **Enter my own** - paste CVE IDs (messy input is fine) or upload a CSV/TXT file.

**Optional environment variables:**
- `NVD_API_KEY` - optional. Without it NVD allows 5 requests / 30s; with it, 50.
  The app works without it, just slower on never-before-seen CVEs.
- `GEMINI_API_KEY` - optional. Enables the AI explanation features.
- `GEMINI_MODEL` - optional, defaults to `gemini-flash-lite-latest`. If that model
  is overloaded (Gemini returns 503) the AI layer retries with backoff and then
  falls back to other verified models automatically.

### Dependency note

This project uses **`google-genai`**, Google's current, maintained Gemini SDK.

It originally used the older `google-generativeai` package, but Google has
**deprecated** that one (it prints an end-of-support warning on import), and it
failed to install on the deployment host - so the AI layer was migrated to
`google-genai`. Only `ai.py` needed to change, because the AI layer is isolated
behind `is_available()` / `plain_english()` / `remediation_writeup()`; scoring
and fetching were untouched.

Versions are intentionally **not pinned**: the code targets current APIs (e.g.
`Styler.map`, which replaced the removed `Styler.applymap`), so tracking current
releases is the correct target rather than freezing older ones.

---

## Deploying it (Streamlit Community Cloud - free)

The demo works on the deployed app with no keys, because the 30 demo CVEs' NVD
data is committed in `cache/nvd_cache.json` (EPSS and KEV are fetched live).

1. Push this folder to a **GitHub** repository.
2. Go to **https://share.streamlit.io**, sign in with GitHub, and click
   **Create app → Deploy a public app from GitHub**.
3. Pick the repo/branch, set **Main file path** to `app.py`, and Deploy.
4. (Optional, for the AI features) open the app's **⋮ → Settings → Secrets** and
   paste your key(s) in TOML form - the same format as
   `.streamlit/secrets.toml.example`:
   ```toml
   GEMINI_API_KEY = "your-key"
   ```
   Save; the app reboots with the AI panels enabled.

**Secrets never live in the repo.** `.streamlit/secrets.toml` and `.env` are
git-ignored; on the host you set them in the Secrets panel. The app reads keys
from environment variables and also bridges `st.secrets` into them, so it works
either way.

Any host that runs `streamlit run app.py` works too (Hugging Face Spaces, Render,
Railway, a container). Set the same environment variables as secrets there.

---

## Files

| File | Purpose |
|------|---------|
| `app.py` | Streamlit UI: sidebar, input modes, presets, results table, breakdowns, CSV |
| `sources.py` | Fetching + caching from NVD, EPSS, KEV |
| `scoring.py` | The ranking arithmetic (threat, impact, base, multipliers) |
| `parsing.py` | Cleans messy CVE input; routes no-CVE lines to manual review |
| `ai.py` | Optional Gemini explanation layer (never ranks) |
| `cache/` | `nvd_cache.json` (permanent), `demo_cves.json` (the 30), `ai_cache.json` |

Each module has a `python <file>.py` self-test you can run from the terminal.
