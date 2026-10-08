import re
import sys
from datetime import datetime, date

from tools.nvd_tool import nvd_lookup
from tools.exa_tool import exa_exploit_search

from risk_fusion import (
    RiskFusionInputs,
    compute_fused_score,
    priority_from_score,
)


def extract_cvss(text):
    match = re.search(
        r"Base Score:\s*([0-9]+(?:\.[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    return float(match.group(1)) if match else None


def extract_latest_date(text):
    dates = re.findall(
        r"EVIDENCE\|(\d{4}-\d{2}-\d{2})\|",
        text,
    )

    if not dates:
        return None

    return max(
        datetime.strptime(d, "%Y-%m-%d").date()
        for d in dates
    )


def classify_exploit_maturity(exa_text):
    """
    Estimate exploit maturity using only Exa evidence.

    1.0 = strong evidence of active exploitation
    0.5 = public PoC / exploit code
    0.0 = insufficient exploit evidence
    """

    text = exa_text.upper()

    active_terms = [
        "ACTIVELY EXPLOITED",
        "ACTIVELY BEING EXPLOITED",
        "EXPLOITED IN THE WILD",
        "EXPLOITED IN-WILD",
        "BROADLY EXPLOITED",
        "MASS EXPLOITATION",
        "ONGOING EXPLOITATION",
        "WIDESPREAD EXPLOITATION",
    ]

    poc_terms = [
        "PROOF-OF-CONCEPT",
        "PROOF OF CONCEPT",
        "EXPLOIT CODE",
        "EXPLOIT AVAILABLE",
        "PUBLIC EXPLOIT",
        "POC AVAILABLE",
    ]

    if any(term in text for term in active_terms):
        return 1.0, "ACTIVE"

    if any(term in text for term in poc_terms):
        return 0.5, "POC"

    return 0.0, "NONE"


def calculate_score(cvss, maturity, evidence_date):
    if cvss is None:
        return None, None

    if evidence_date:
        days = max((date.today() - evidence_date).days, 0)
    else:
        days = 3650

    inputs = RiskFusionInputs(
        base_cvss=cvss,
        exploit_maturity=maturity,
        days_since_evidence=days,
    )

    score = compute_fused_score(inputs)

    return score, days


def load_cves(path):
    with open(path, encoding="utf-8") as f:
        return [
            line.strip().upper()
            for line in f
            if line.strip()
        ]


def process_group(cve_list, group_name):
    results = []

    print(f"\n=== {group_name} ===")

    for index, cve_id in enumerate(cve_list, start=1):

        print(f"\n[{index}/{len(cve_list)}] {cve_id}")

        try:
            nvd_result = nvd_lookup.run(cve_id)
            exa_result = exa_exploit_search.run(cve_id)

            cvss = extract_cvss(nvd_result)
            latest_date = extract_latest_date(exa_result)

            maturity, prediction = classify_exploit_maturity(
                exa_result
            )

            score, days = calculate_score(
                cvss,
                maturity,
                latest_date,
            )

            results.append({
                "cve": cve_id,
                "cvss": cvss,
                "prediction": prediction,
                "maturity": maturity,
                "evidence_date": latest_date,
                "days": days,
                "score": score,
            })

            print(f"  CVSS: {cvss}")
            print(f"  Prediction: {prediction}")
            print(f"  Maturity: {maturity}")

            if latest_date:
                print(f"  Latest Evidence: {latest_date}")

            if score is not None:
                print(f"  Fused Score: {score:.2f}")
                print(f"  Priority: {priority_from_score(score)}")

        except Exception as e:
            print(f"  ERROR: {e}")

    return results


def calculate_metrics(kev_results, nonkev_results):

    tp = sum(
        r["prediction"] == "ACTIVE"
        for r in kev_results
    )

    fn = sum(
        r["prediction"] != "ACTIVE"
        for r in kev_results
    )

    fp = sum(
        r["prediction"] == "ACTIVE"
        for r in nonkev_results
    )

    tn = sum(
        r["prediction"] != "ACTIVE"
        for r in nonkev_results
    )

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else None
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else None
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else None
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None
        and recall is not None
        and (precision + recall) > 0
        else None
    )

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def average_score(results):

    scores = [
        r["score"]
        for r in results
        if r["score"] is not None
    ]

    return (
        sum(scores) / len(scores)
        if scores
        else None
    )


def print_summary(kev_results, nonkev_results):

    metrics = calculate_metrics(
        kev_results,
        nonkev_results,
    )

    kev_average = average_score(kev_results)
    nonkev_average = average_score(nonkev_results)

    all_results = kev_results + nonkev_results

    overall_average = average_score(all_results)

    print("\n")
    print("=" * 60)
    print("FINAL VALIDATION RESULTS")
    print("=" * 60)

    print("\n=== EXPLOITATION DETECTION ===")

    print(f"TP: {metrics['TP']}")
    print(f"FP: {metrics['FP']}")
    print(f"TN: {metrics['TN']}")
    print(f"FN: {metrics['FN']}")

    if metrics["accuracy"] is not None:
        print(f"Accuracy:  {metrics['accuracy']:.3f}")

    if metrics["precision"] is not None:
        print(f"Precision: {metrics['precision']:.3f}")

    if metrics["recall"] is not None:
        print(f"Recall:    {metrics['recall']:.3f}")

    if metrics["f1"] is not None:
        print(f"F1 Score:  {metrics['f1']:.3f}")

    print("\n=== DYNAMIC RISK SCORE ===")

    if kev_average is not None:
        print(f"Average KEV Score:     {kev_average:.3f}")

    if nonkev_average is not None:
        print(f"Average Non-KEV Score: {nonkev_average:.3f}")

    if overall_average is not None:
        print(f"Overall Average Score: {overall_average:.3f}")

    print("\n=== METHODOLOGY ===")
    print("Positive class: 20 CVEs from CISA KEV.")
    print("Negative class: 20 real NVD CVEs absent from KEV.")
    print("Exa provides independent web exploit intelligence.")
    print("KEV membership is used only as ground truth.")
    print("Risk score represents dynamic remediation urgency,")
    print("not historical KEV membership.")


def main():

    if len(sys.argv) != 3:
        print(
            "Usage: python validation.py "
            "<kev_file> <nonkev_file>"
        )
        sys.exit(1)

    kev_file = sys.argv[1]
    nonkev_file = sys.argv[2]

    kev_cves = load_cves(kev_file)
    nonkev_cves = load_cves(nonkev_file)

    print("CVE Validation Dataset")
    print("----------------------")
    print(f"KEV CVEs:     {len(kev_cves)}")
    print(f"Non-KEV CVEs: {len(nonkev_cves)}")
    print(f"Total CVEs:   {len(kev_cves) + len(nonkev_cves)}")

    kev_results = process_group(
        kev_cves,
        "KEV / EXPLOITED CLASS",
    )

    nonkev_results = process_group(
        nonkev_cves,
        "NON-KEV / NEGATIVE CLASS",
    )

    print_summary(
        kev_results,
        nonkev_results,
    )


if __name__ == "__main__":
    main()