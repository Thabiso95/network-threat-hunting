from pathlib import Path
import pandas as pd

DEFAULT_WINDOW_SECONDS = 60
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "output"


def correlate_alerts(alerts, window_seconds=DEFAULT_WINDOW_SECONDS):
    """Assign related alerts to cases without modifying the input."""
    if window_seconds < 0:
        raise ValueError("window_seconds must be non-negative")

    required = {"source_ip", "destination_ip", "timestamp", "finding_type"}
    missing = required - set(alerts.columns)
    if missing:
        raise ValueError(f"Missing required alert columns: {sorted(missing)}")

    enriched = alerts.copy().reset_index(drop=True)
    enriched["alert_id"] = [
        f"NTH-001-ALERT-{number:03d}"
        for number in range(1, len(enriched) + 1)
    ]
    enriched["case_id"] = pd.Series(index=enriched.index, dtype="object")
    enriched["correlation_reason"] = pd.Series(
        index=enriched.index, dtype="object"
    )

    case_columns = [
        "case_id", "source_ip", "destination_ip", "first_seen",
        "last_seen", "alert_count", "finding_types", "severity",
        "overlapping_detections", "case_summary",
    ]

    if enriched.empty:
        return enriched.assign(
            alert_id=pd.Series(dtype="object"),
            case_id=pd.Series(dtype="object"),
            correlation_reason=pd.Series(dtype="object"),
        ), pd.DataFrame(columns=case_columns)

    enriched["_parsed_timestamp"] = pd.to_datetime(
        enriched["timestamp"], utc=True, errors="coerce"
    )
    if enriched["_parsed_timestamp"].isna().any():
        raise ValueError("Every alert must have a valid timestamp.")

    if enriched[["source_ip", "destination_ip"]].isna().any().any():
        raise ValueError("Alerts must have source and destination IPs.")

    # Build time-bounded clusters for each source/destination pair.
    clusters = []
    pair_groups = enriched.groupby(
        ["source_ip", "destination_ip"], sort=True, dropna=False
    )

    for (source_ip, destination_ip), pair in pair_groups:
        pair = pair.sort_values(
            ["_parsed_timestamp", "alert_id"], kind="stable"
        )
        current_indices = []
        cluster_start = None

        for index, row in pair.iterrows():
            timestamp = row["_parsed_timestamp"]

            if (
                cluster_start is None
                or (timestamp - cluster_start).total_seconds() > window_seconds
            ):
                if current_indices:
                    clusters.append({
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "indices": current_indices,
                        "first_seen": cluster_start,
                    })
                current_indices = [index]
                cluster_start = timestamp
            else:
                current_indices.append(index)

        if current_indices:
            clusters.append({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "indices": current_indices,
                "first_seen": cluster_start,
            })

    # Stable case IDs based on case first-seen time.
    clusters.sort(
        key=lambda item: (
            item["first_seen"],
            str(item["source_ip"]),
            str(item["destination_ip"]),
        )
    )

    case_rows = []
    for number, cluster in enumerate(clusters, start=1):
        case_id = f"NTH-001-CASE-{number:03d}"
        indices = cluster["indices"]
        case_alerts = enriched.loc[indices].sort_values(
            ["_parsed_timestamp", "alert_id"], kind="stable"
        )

        types = list(dict.fromkeys(case_alerts["finding_type"].astype(str)))
        overlap = (
            "Cumulative high-transfer activity" in types
            and "High-transfer event" in types
        )
        reason = (
            f"Same source/destination pair within {window_seconds} seconds"
            if len(indices) > 1
            else f"Standalone alert; no other alert for this pair within "
                 f"{window_seconds} seconds"
        )

        enriched.loc[indices, "case_id"] = case_id
        enriched.loc[indices, "correlation_reason"] = reason

        if "severity" in case_alerts.columns:
            severities = list(dict.fromkeys(
                case_alerts["severity"].dropna().astype(str)
            ))
            severity = "; ".join(severities) if severities else "Not assigned"
        else:
            severity = "Not assigned"

        first_seen = case_alerts["_parsed_timestamp"].min()
        last_seen = case_alerts["_parsed_timestamp"].max()

        summary = (
            f"{len(indices)} alert(s) associated with "
            f"{cluster['source_ip']} -> {cluster['destination_ip']}. "
            f"Detection types: {', '.join(types)}."
        )
        if overlap:
            summary += (
                " Individual and cumulative transfer detections overlap; "
                "do not treat their byte counts as separate traffic."
            )

        case_rows.append({
            "case_id": case_id,
            "source_ip": cluster["source_ip"],
            "destination_ip": cluster["destination_ip"],
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "alert_count": len(indices),
            "finding_types": "; ".join(types),
            "severity": severity,
            "overlapping_detections": overlap,
            "case_summary": summary,
        })

    enriched = enriched.drop(columns=["_parsed_timestamp"])
    return enriched, pd.DataFrame(case_rows, columns=case_columns)


def export_correlated_results(
    correlated_alerts,
    cases,
    output_dir=OUTPUT_DIR,
):
    """Export enriched alerts and case summaries to separate CSV files."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    correlated_path = output_dir / "correlated-alerts.csv"
    cases_path = output_dir / "cases.csv"

    correlated_alerts.to_csv(correlated_path, index=False)
    cases.to_csv(cases_path, index=False)

    return correlated_path, cases_path
