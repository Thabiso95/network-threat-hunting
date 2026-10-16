"""Explainable triage scoring for synthetic network cases."""

from pathlib import Path
import pandas as pd

INPUT = Path("output/cases.csv")
OUTPUT = Path("output/prioritized-cases.csv")

REQUIRED = {
    "case_id", "source_ip", "destination_ip",
    "alert_count", "finding_types", "overlapping_detections",
}

def prioritize_cases(cases):
    missing = REQUIRED - set(cases.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    result = cases.copy()

    if result.empty:
        result["priority_score"] = pd.Series(dtype="int64")
        result["priority"] = pd.Series(dtype="object")
        result["priority_reasons"] = pd.Series(dtype="object")
        result["recommended_next_steps"] = pd.Series(dtype="object")
        return result

    scores, priorities, reasons_list, actions_list = [], [], [], []

    for _, case in result.iterrows():
        findings = {
            item.strip().casefold()
            for item in str(case["finding_types"]).split(";")
            if item.strip()
        }

        try:
            alert_count = int(case["alert_count"])
        except (TypeError, ValueError):
            raise ValueError("alert_count must be a non-negative integer")

        if alert_count < 0:
            raise ValueError("alert_count must be non-negative")

        score = 10
        reasons = ["Base score: +10 for analyst review"]

        if any("potential port scan" in f for f in findings):
            score += 20
            reasons.append("+20: potential port-scan detection")

        if any("high-transfer event" in f for f in findings):
            score += 25
            reasons.append("+25: individual high-transfer detection")

        if any("cumulative high-transfer" in f for f in findings):
            score += 20
            reasons.append("+20: cumulative high-transfer detection")

        if alert_count > 1:
            bonus = min(alert_count - 1, 5) * 3
            score += bonus
            reasons.append(f"+{bonus}: related-alert-count bonus")

        overlap = str(case["overlapping_detections"]).strip().casefold()
        if overlap in {"true", "1", "yes"}:
            score += 5
            reasons.append("+5: overlapping detections need deduplication")

        if score >= 45:
            priority = "High"
            actions = (
                "Review underlying events and timestamps; validate transfer "
                "totals and overlap; check destination context, asset "
                "ownership, and whether activity was authorised."
            )
        elif score >= 25:
            priority = "Medium"
            actions = (
                "Validate the detection against raw events; review timing, "
                "destination context, expected behaviour, and false-positive "
                "possibilities."
            )
        else:
            priority = "Low"
            actions = (
                "Perform an initial evidence review and determine whether "
                "additional context warrants escalation."
            )

        scores.append(score)
        priorities.append(priority)
        reasons_list.append("; ".join(reasons))
        actions_list.append(actions)

    result["priority_score"] = scores
    result["priority"] = priorities
    result["priority_reasons"] = reasons_list
    result["recommended_next_steps"] = actions_list

    return result.sort_values(
        ["priority_score", "case_id"],
        ascending=[False, True],
        kind="stable",
    ).reset_index(drop=True)


def main():
    cases = pd.read_csv(INPUT)
    result = prioritize_cases(cases)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(OUTPUT, index=False)

    print("CASE PRIORITISATION — TRAINING HEURISTIC")
    print("=" * 55)
    if result.empty:
        print("No cases to prioritise.")
    else:
        print(result[
            ["case_id", "alert_count", "priority_score", "priority"]
        ].to_string(index=False))
    print(f"\nOutput: {OUTPUT}")
    print("Scores guide triage; they do not prove malicious activity.")
    print("Evidence is synthetic.")


if __name__ == "__main__":
    main()
