"""
scoring.py - the NextPatch ranking arithmetic.

This is deliberately plain arithmetic: no machine learning, no AI, nothing that
can't be shown on screen. Every number in the final ranking must be explainable
to a non-technical client, because they have to justify their patching order to
auditors. An unexplainable priority list is useless in security work.

The model, in four steps:

  1. THREAT (0-10) - is anyone actually attacking this?
       on KEV            -> 10          (confirmed fact beats any prediction)
       else, has EPSS    -> EPSS * 10   (EPSS 0.40 -> 4.0)
       else              -> None        ('Unknown' - not 0, not 'safe')

  2. IMPACT (0-10) - how bad if it works?
       impact = CVSS base score from NVD

  3. BASE
       base = (threat * 0.6) + (impact * 0.4)
       Threat is weighted heavier: a flaw nobody attacks can't hurt you,
       however severe it looks on paper.

  4. ASSET CONTEXT multipliers (only the operator knows these)
       internet-facing -> * 1.5   (network-exploitable flaws only)
       sensitive data  -> * 1.3
       final = base * (every applicable multiplier)

  5. TEST-MACHINE CAP
       A throwaway test box is a CEILING, not a multiplier: the score is
       clamped to TEST_MACHINE_CAP and the two boosts above are skipped.
       See the constant for why a multiplier was the wrong shape here.

The weights (0.6, 0.4, 1.5, 1.3 and the 5.0 cap) are a judgement call, NOT
science. They are surfaced as configurable in the UI and would be tuned with a
real security team. They are not presented as authoritative.
"""

from __future__ import annotations

# --- configurable weights (a judgement call, not science) ------------------
THREAT_WEIGHT = 0.6
IMPACT_WEIGHT = 0.4

MULT_INTERNET = 1.5   # reachable from the internet
MULT_SENSITIVE = 1.3  # holds sensitive data

# A throwaway test machine is a CEILING, not a multiplier.
#
# Why not a multiplier: multipliers compose, so internet(1.5) x sensitive(1.3)
# x test(0.5) = 0.975, which meant a disposable box cancelled almost exactly
# back to full priority. A ceiling cannot be defeated by any combination.
#
# It also OVERRIDES the other two boosts. If we would wipe the machine anyway,
# how exposed or sensitive it is does not earn it emergency attention. (Keeping
# the boosts and dropping the 0.5 would be worse still: a low-severity flaw on a
# test box would score base x 1.95, i.e. HIGHER than on an unflagged machine.)
# So a test box is scored on its base risk alone, then clamped to this ceiling,
# which keeps it out of the "fix first" and "high" bands entirely.
TEST_MACHINE_CAP = 5.0


# --- threat state labels ---------------------------------------------------
STATE_CONFIRMED = "Confirmed"  # on KEV: someone IS attacking it
STATE_LIKELY = "Likely"        # meaningful EPSS: prediction says attacks are plausible
STATE_UNKNOWN = "Unknown"      # no KEV, no meaningful EPSS: not seen exploited YET

# EPSS below this we treat as "no meaningful signal" for the state label.
# (The numeric score still uses the exact EPSS value; this only affects whether
# we call the state 'Likely' or 'Unknown'.)
LIKELY_THRESHOLD = 0.10  # >=10% predicted exploitation -> 'Likely'; below -> 'Unknown'.
                         # (Configurable judgement call, like the scoring weights.)


def compute_threat(on_kev: bool, epss: float | None):
    """
    Return (threat_score, source_label).

    threat_score is 0-10, or None when we genuinely have no threat data.
    source_label explains where the number came from, for the breakdown view.
    """
    if on_kev:
        return 10.0, "On CISA KEV (confirmed active exploitation)"
    if epss is not None:
        return epss * 10.0, f"EPSS {epss:.3f} x 10"
    return None, "No EPSS data"


def threat_state(on_kev: bool, epss: float | None) -> str:
    """The honest label for how sure we are that this is a real threat."""
    if on_kev:
        return STATE_CONFIRMED
    if epss is not None and epss >= LIKELY_THRESHOLD:
        return STATE_LIKELY
    return STATE_UNKNOWN


def is_network_exploitable(attack_vector) -> bool:
    """
    Can an attacker on the internet reach this flaw directly?

    NETWORK       -> yes (remotely exploitable over the network)
    ADJACENT_NETWORK / LOCAL / PHYSICAL -> no (needs local/adjacent access first)
    None (unknown) -> assume yes, so we don't accidentally under-prioritise a
                      flaw whose vector we simply don't have.
    """
    return attack_vector is None or attack_vector == "NETWORK"


def score_one(cve_id: str, cvss, epss, on_kev: bool, context: dict,
              attack_vector=None) -> dict:
    """
    Score a single CVE and return a fully broken-down result dict.

    Args:
      cvss          : CVSS base score (0-10) or None if NVD had none.
      epss          : EPSS probability (0-1) or None if EPSS had no data.
      on_kev        : True if the CVE is on the CISA KEV list.
      context       : {"internet": bool, "sensitive": bool, "test": bool}
      attack_vector : NVD attack vector (NETWORK / LOCAL / ...) or None.

    Every intermediate value is returned so the UI can show the full chain.
    """
    threat, threat_src = compute_threat(on_kev, epss)
    impact = cvss  # impact IS the CVSS base score

    # Base score. If either input is missing we still compute what we can,
    # treating a missing piece as 0 for the arithmetic but recording that it
    # was missing so the UI can flag it honestly.
    threat_component = (threat if threat is not None else 0.0) * THREAT_WEIGHT
    impact_component = (impact if impact is not None else 0.0) * IMPACT_WEIGHT
    base = threat_component + impact_component

    # Asset-context multipliers.
    #
    # The internet-facing boost is applied ONLY to network-exploitable flaws.
    # A local privilege-escalation flaw isn't any easier to hit just because the
    # box faces the internet - the attacker still needs local access first. This
    # is what makes switching asset presets actually re-order the list.
    net_exploitable = is_network_exploitable(attack_vector)
    internet_requested = bool(context.get("internet"))
    internet_applied = internet_requested and net_exploitable

    # A test machine is a ceiling, and it overrides the other two boosts
    # entirely (see TEST_MACHINE_CAP for why).
    test_machine = bool(context.get("test"))
    internet_applied = internet_applied and not test_machine
    sensitive_applied = bool(context.get("sensitive")) and not test_machine

    multipliers = []
    if internet_applied:
        multipliers.append(("Internet-facing (network-exploitable)", MULT_INTERNET))
    if sensitive_applied:
        multipliers.append(("Holds sensitive data", MULT_SENSITIVE))

    final = base
    for _label, factor in multipliers:
        final *= factor

    # Clamp a throwaway box to the ceiling. Anything above it ties at the cap,
    # so score_all breaks ties on the uncapped score to keep ordering readable.
    score_before_cap = final
    cap_applied = test_machine and final > TEST_MACHINE_CAP
    if cap_applied:
        final = TEST_MACHINE_CAP

    return {
        "cve": cve_id,
        "cvss": cvss,
        "epss": epss,
        "on_kev": on_kev,
        "attack_vector": attack_vector,
        # scored pieces
        "threat": threat,                 # None means 'Unknown'
        "threat_source": threat_src,
        "impact": impact,
        "threat_component": threat_component,
        "impact_component": impact_component,
        "base": base,
        "multipliers": multipliers,       # list of (label, factor)
        "score_before_cap": score_before_cap,
        "cap_applied": cap_applied,
        "test_machine": test_machine,
        "test_cap": TEST_MACHINE_CAP,
        "final_score": final,
        # context bookkeeping (for the breakdown view)
        "net_exploitable": net_exploitable,
        "internet_requested": internet_requested,
        "internet_applied": internet_applied,
        # honest labels
        "state": threat_state(on_kev, epss),
        "epss_missing": epss is None,
        "cvss_missing": cvss is None,
    }


def score_all(records, context: dict):
    """
    Score a list of records and return them sorted by final_score, highest first.

    Each input record is a dict: {cve, cvss, epss, on_kev}.
    """
    scored = []
    for r in records:
        item = score_one(r["cve"], r.get("cvss"), r.get("epss"),
                         r.get("on_kev", False), context,
                         attack_vector=r.get("attack_vector"))
        # carry the descriptive fields through so the table, CSV and AI layer
        # can use them (scoring itself doesn't need them)
        item["description"] = r.get("description", "")
        item["product"] = r.get("product", "")
        scored.append(item)
    # Break ties on the pre-cap score: on a test machine everything above the
    # ceiling shares the same final score, but we still want the worst first.
    scored.sort(key=lambda x: (x["final_score"], x["score_before_cap"]), reverse=True)
    return scored


# ===========================================================================
# self-test against the worked example from the project brief
#   Flaw A: CVSS 9.8, not on KEV, EPSS 0.005, not internet-facing -> 3.95
#   Flaw B: CVSS 6.5, on KEV,     no EPSS,     internet-facing     -> 12.9
# ===========================================================================

if __name__ == "__main__":
    plain_ctx = {"internet": False, "sensitive": False, "test": False}
    internet_ctx = {"internet": True, "sensitive": False, "test": False}

    # Flaw B is network-exploitable, so the internet boost applies -> 12.9,
    # exactly as in the brief's worked example.
    a = score_one("FLAW-A", cvss=9.8, epss=0.005, on_kev=False, context=plain_ctx,
                  attack_vector="NETWORK")
    b = score_one("FLAW-B", cvss=6.5, epss=None, on_kev=True, context=internet_ctx,
                  attack_vector="NETWORK")

    print("Flaw A - high CVSS (9.8), nobody attacking it")
    print(f"  threat = {a['threat']:.2f}   base = {a['base']:.2f}   FINAL = {a['final_score']:.2f}")
    print(f"  expected: threat 0.05, base 3.95, final 3.95")

    print("\nFlaw B - moderate CVSS (6.5), confirmed under attack, internet-facing")
    print(f"  threat = {b['threat']:.2f}   base = {b['base']:.2f}   FINAL = {b['final_score']:.2f}")
    print(f"  expected: threat 10.0, base 8.60, final 12.9")

    ok_a = abs(a["final_score"] - 3.95) < 0.001
    ok_b = abs(b["final_score"] - 12.9) < 0.001
    print("\nFlaw A matches worked example:", ok_a)
    print("Flaw B matches worked example:", ok_b)
    print("\nTHE REVERSAL: Flaw A looks scarier by CVSS (9.8 vs 6.5),")
    print(f"but Flaw B outranks it {b['final_score']:.2f} to {a['final_score']:.2f}.")
    assert ok_a and ok_b, "Scoring does not match the worked example!"

    # attack-vector demo: the SAME internet-facing context must NOT boost a
    # local-only flaw, so it can now rank below a network flaw it used to tie.
    b_local = score_one("FLAW-B-LOCAL", cvss=6.5, epss=None, on_kev=True,
                        context=internet_ctx, attack_vector="LOCAL")
    print(f"\nAttack-vector check: a LOCAL flaw with the same inputs scores "
          f"{b_local['final_score']:.2f} (no internet boost) vs {b['final_score']:.2f} "
          f"for the NETWORK flaw.")
    assert abs(b_local["final_score"] - 8.6) < 0.001, "local flaw should not get the internet boost"
    print("PASS - internet boost only applies to network-exploitable flaws,")
    print("       so switching asset presets now re-orders the list.")

    # test-machine cap: a disposable box must never reach production priority,
    # no matter what else is ticked. The old x0.5 multiplier could be cancelled
    # out (1.5 x 1.3 x 0.5 = 0.975); a ceiling cannot be.
    everything_ctx = {"internet": True, "sensitive": True, "test": True}
    t = score_one("FLAW-TEST", cvss=10.0, epss=None, on_kev=True,
                  context=everything_ctx, attack_vector="NETWORK")
    print(f"\nTest-machine cap: worst possible flaw on a throwaway box scores "
          f"{t['final_score']:.2f} (base {t['base']:.2f}, capped at {t['test_cap']:.1f}).")
    assert t["final_score"] == TEST_MACHINE_CAP, "test box must be clamped to the cap"
    assert t["multipliers"] == [], "test box must skip the internet/sensitive boosts"
    print("PASS - a test machine is a ceiling that overrides the other boosts,")
    print("       so no combination of ticks can push it back to full priority.")
