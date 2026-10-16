from pathlib import Path
import pandas as pd

DATA_FILE = Path(__file__).resolve().parents[1] / "evidence" / "network-traffic.csv"
OUTPUT_FILE = Path(__file__).resolve().parents[1] / "output" / "alerts.csv"

PORT_THRESHOLD = 10
WINDOW_SECONDS = 300
TRANSFER_THRESHOLD = 900_000


def load_events(path=DATA_FILE):
    """Load network events and validate required fields."""
    df = pd.read_csv(path)
    required = {
        "timestamp", "source_ip", "destination_ip",
        "destination_port", "protocol", "connection_state",
        "bytes_sent",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="raise")
    df["destination_port"] = pd.to_numeric(df["destination_port"], errors="raise")
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="raise")

    if not df["destination_port"].between(1, 65535).all():
        raise ValueError("Destination ports must be between 1 and 65535.")
    if (df["bytes_sent"] < 0).any():
        raise ValueError("bytes_sent cannot be negative.")
    return df


def detect_port_scans(events):
    """Identify source/destination pairs contacting 10+ ports in five minutes."""
    findings = []

    for (source, destination), group in events.groupby(
        ["source_ip", "destination_ip"]
    ):
        group = group.sort_values("timestamp").reset_index(drop=True)
        left = 0

        for right in range(len(group)):
            while (
                group.loc[right, "timestamp"] - group.loc[left, "timestamp"]
            ).total_seconds() > WINDOW_SECONDS:
                left += 1

            window = group.iloc[left:right + 1]
            ports = sorted(window["destination_port"].unique())

            if len(ports) >= PORT_THRESHOLD:
                findings.append({
                    "finding_type": "Potential port scan",
                    "source_ip": source,
                    "destination_ip": destination,
                    "destination_port": "",
                    "timestamp": window["timestamp"].iloc[0].isoformat(),
                    "event_count": len(window),
                    "unique_ports": len(ports),
                    "bytes_sent": "",
                    "severity": "Medium - provisional",
                    "reason": (
                        f"{len(ports)} distinct destination ports contacted "
                        f"within {WINDOW_SECONDS} seconds"
                    ),
                    "recommended_actions": (
                        "Review connection states and firewall logs; identify "
                        "both assets; check related alerts and successful connections."
                    ),
                })
                break

    return pd.DataFrame(findings)


def detect_high_transfers(events):
    """Identify individual events meeting the configured byte threshold."""
    findings = events.loc[
        events["bytes_sent"] >= TRANSFER_THRESHOLD
    ].copy()

    if findings.empty:
        return pd.DataFrame(columns=[
            "finding_type", "source_ip", "destination_ip", "destination_port",
            "timestamp", "event_count", "bytes_sent", "severity", "reason",
            "recommended_actions"
        ])

    findings["finding_type"] = "High-transfer event"
    findings["timestamp"] = findings["timestamp"].apply(lambda value: value.isoformat())
    findings["event_count"] = 1
    findings["severity"] = "Medium - provisional"
    findings["reason"] = (
        f"Individual event sent at least {TRANSFER_THRESHOLD:,} bytes"
    )
    findings["recommended_actions"] = (
        "Identify the application and asset owner; compare with normal traffic; "
        "review destination and surrounding connections; confirm authorization."
    )

    return findings[[
        "finding_type", "source_ip", "destination_ip", "destination_port",
        "timestamp", "event_count", "bytes_sent", "severity", "reason",
        "recommended_actions"
    ]]


def build_alerts(events):
    """Combine all detection results into one consistent alert table."""
    scans = detect_port_scans(events)
    transfers = detect_high_transfers(events)
    columns = [
        "finding_type", "source_ip", "destination_ip", "destination_port",
        "timestamp", "event_count", "bytes_sent", "severity", "reason",
        "recommended_actions"
    ]

    frames = [frame for frame in (scans, transfers) if not frame.empty]
    if not frames:
        return pd.DataFrame(columns=columns)

    return pd.concat(frames, ignore_index=True)[columns]


def export_alerts(alerts, path=OUTPUT_FILE):
    """Write alerts to CSV and return the destination path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(path, index=False)
    return path


def main():
    events = load_events()
    alerts = build_alerts(events)
    output_path = export_alerts(alerts)

    print("=" * 64)
    print("NETWORK THREAT HUNTING — CASE NTH-001")
    print("=" * 64)
    print(f"Events analysed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    if alerts.empty:
        print("No findings met the configured detection thresholds.")
    else:
        print(alerts[[
            "finding_type", "source_ip", "destination_ip",
            "severity", "reason"
        ]].to_string(index=False))

    print(f"\nCSV alert export: {output_path}")
    print("Severity is provisional; these are investigation leads.")
    print("Synthetic dataset only; no live network or SIEM was queried.")


if __name__ == "__main__":
    main()
