from dataclasses import dataclass
import math


@dataclass
class RiskFusionInputs:
    base_cvss: float
    exploit_maturity: float
    days_since_evidence: float
    w1: float = 0.5
    w2: float = 5.0
    decay_lambda: float = 0.05


def compute_fused_score(inputs: RiskFusionInputs) -> float:
    decay = math.exp(
        -inputs.decay_lambda * max(inputs.days_since_evidence, 0)
    )

    dynamic_component = (
        inputs.w2 * inputs.exploit_maturity * decay
    )

    static_component = inputs.w1 * inputs.base_cvss

    return round(
        min(static_component + dynamic_component, 10.0),
        2
    )


def priority_from_score(score: float) -> str:
    if score >= 8.5:
        return "P0 - Patch within 24 hours"
    elif score >= 7.0:
        return "P1 - Patch within 3 days"
    elif score >= 5.0:
        return "P2 - Patch within 2 weeks"
    else:
        return "P3 - Patch in next regular cycle"


def priority_from_score_with_kev(score: float, is_kev: bool) -> str:
    """
    Applies CISA KEV as an authoritative exploitation signal.

    A CVE confirmed in CISA KEV cannot be assigned a priority
    lower than P1, even if exploitation evidence has become old.
    """

    priority = priority_from_score(score)

    if is_kev and priority.startswith(("P2", "P3")):
        return "P1 - Patch within 3 days"

    return priority


if __name__ == "__main__":
    tests = [
        ("Fresh active exploit", 7.0, 1.0, 0, False),
        ("30-day active exploit", 7.0, 1.0, 30, False),
        ("30-day KEV", 7.0, 1.0, 30, True),
        ("No exploit evidence", 7.0, 0.0, 0, False),
        ("High CVSS, KEV", 8.8, 0.0, 30, True),
    ]

    for name, cvss, maturity, age, is_kev in tests:
        inputs = RiskFusionInputs(
            base_cvss=cvss,
            exploit_maturity=maturity,
            days_since_evidence=age,
        )

        score = compute_fused_score(inputs)
        priority = priority_from_score_with_kev(score, is_kev)

        print(
            f"{name:25} "
            f"Score={score:4.2f} "
            f"KEV={is_kev} "
            f"Priority={priority}"
        )