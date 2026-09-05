# NextPatch — design decisions and why

This document records *why* NextPatch is built the way it is. Every choice below
is meant to be defensible in a technical interview. The README covers *what* it
does and how to run it; this covers the reasoning.

---

## 1. The core bet

**Sorting vulnerabilities by CVSS sorts by the wrong thing.** CVSS measures how bad
a flaw is *if* exploited, not whether it *is* being exploited. So NextPatch mixes
paper severity with real-world threat evidence and ranks by what will actually get
you breached. The single most important artifact in the whole project is *the
reversal*: a moderate-CVSS flaw that's under active attack outranking a
high-CVSS flaw that nobody is touching.

---

## 2. Three sources, three caching rules

**Decision:** cache NVD to disk forever; always fetch EPSS and KEV fresh.

**Why:** the entire argument is that real-world threat changes while paper severity
stays frozen. EPSS updates daily and KEV grows regularly; if we cached them the
tool would become a one-day snapshot and the argument would collapse. NVD, by
contrast, is effectively immutable per-CVE (a description and CVSS don't change
after publication) *and* it's the slow, rate-limited source. So the one source
that's safe to cache forever is exactly the one it's most valuable to cache. The
fast sources are the ones we must keep live — and they're fast precisely because
EPSS accepts all CVEs in one request and KEV is a single file.

**Consequence for the demo:** the 30 demo CVEs have their NVD data pre-cached, so
"Load example" opens instantly and works even with NVD offline. EPSS/KEV are still
fetched fresh (fast).

---

## 3. The score is plain arithmetic, not ML

**Decision:** no machine learning, no AI, in the ranking. Just `+` and `×`.

**Why:** clients must justify their patching order to auditors. If someone asks
"why is this ranked third?", the answer has to be arithmetic we can put on screen,
not "the model decided." An unexplainable priority list is unusable in security
work, and a model can't be audited. Keeping the score to four visible steps
(threat → impact → base → multipliers) is a feature, not a limitation.

- **Threat weighted 0.6 vs impact 0.4:** a flaw nobody attacks can't hurt you,
  however severe it looks, so real-world threat should dominate.
- **KEV beats EPSS:** a confirmed fact beats a prediction. On KEV → threat = 10
  regardless of EPSS.
- **The weights are a judgement call, not science.** They're labelled configurable
  in the UI and would be tuned with a real security team. We never present them as
  authoritative.

---

## 4. Attack-vector-aware internet multiplier

**Decision:** the "internet-facing ×1.5" boost applies only to
**network-exploitable** flaws (CVSS attack vector = NETWORK), not to local-only
ones. Unknown vector is treated as network (cautious default).

**Why this was added:** with a single global multiplier, changing the asset
context multiplies *every* flaw's score by the same constant — which rescales the
numbers but can never change their order. That contradicts the goal of having
preset-switching *re-order* the list. Gating the internet boost on the attack
vector fixes this and is also simply more correct: a local privilege-escalation
flaw is no easier to reach just because the machine faces the internet — the
attacker still needs local access first. So on a public web server, a
network-exploitable flaw (e.g. Zerologon) rightly jumps above a local-only
privilege-escalation flaw it would otherwise tie with.

**Scope note:** only the *internet* multiplier is vector-aware. "Sensitive data"
and "test machine" remain global, because they describe consequences and
environment rather than reachability. This was a deliberate, minimal change to the
specified model, chosen because it's the one that makes the presets meaningfully
re-order.

---

## 5. Missing data is shown, never faked

**Decision:** three explicit states — **Confirmed** (KEV), **Likely** (meaningful
EPSS), **Unknown** (neither) — and a separate **Needs manual review** list.

**Why:** the honest failure mode matters in security. A flaw that isn't on KEV and
has negligible EPSS has not been *seen* exploited *yet* — that is not the same as
"safe". Most tools silently sort these last, which is a claim they can't support.
NextPatch labels the state **Unknown** and shows it. Likewise, EPSS "no data" is
shown as such, never as a probability of 0. And an input line with no CVE number
can't be scored at all (the databases are CVE-keyed), so it's parked under
*Needs manual review* instead of vanishing.

---

## 6. The preset fills the checkboxes but never locks them

**Decision:** the asset-context preset dropdown pre-fills the three checkboxes as a
starting point; the checkboxes stay fully editable, and manual edits stick.

**Why:** presets are a convenience, not a policy. A user who picks "Public Web
Server" and then unticks "sensitive data" means it — that edit must persist. This
is implemented by making the checkboxes own their own session state and having the
preset only *write* to them on change (never on every rerun).

---

## 7. The AI explains; it never ranks

**Decision:** Gemini is used for plain-English translation and remediation
write-ups only. It's optional, cached to disk, and completely removed from the
scoring path.

**Why:** same reason as §3 — the ranking must stay auditable. The AI is a writing
aid (it saves the report-writing time pen-testers spend), fed the already-computed
numbers as facts and told not to invent data or argue about priority. If the key
is missing the tool still fully works; a missing AI key must never break the core.

---

## 8. Demo curation is data-driven

**Decision:** the 30 demo CVEs were chosen by fetching real CVSS/EPSS/KEV for a
larger candidate pool and picking from the actual numbers, not from memory.

**Why:** the demo has to *actually* show the reversal with live data. The set spans
famous flaws, high-CVSS-but-dormant flaws (scary ≠ urgent), moderate-CVSS flaws
under active attack (the reverse), and a few unremarkable ones so the list looks
realistic. The clearest single case in the demo: **Zerologon (CVE-2020-1472,
CVSS 5.5, on KEV)** outranking **CVE-2021-22118 (CVSS 7.8, EPSS 0.4%, not on
KEV)** — a lower-severity flaw beating a higher-severity one because it's the one
actually being exploited.

---

## 9. Honesty

Combining KEV + EPSS + NVD is **established practice** in vulnerability management;
this project doesn't claim to have invented it. What this implementation adds is
the asset-context layer (including the attack-vector-aware multiplier), the
explicit *Unknown* state, and the AI explanation layer. There are no benchmarks,
accuracy figures, or "reduces triage time by X%" claims anywhere in the project —
it makes none, because it's a transparent prioritisation aid, not a predictor.
