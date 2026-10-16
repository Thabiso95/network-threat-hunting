from pathlib import Path
import pandas as pd

DATA_FILE = Path(__file__).resolve().parents[1] / "evidence" / "network-traffic.csv"

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

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], utc=True, errors="raise"
    )
    df["destination_port"] = pd.to_numeric(
        df["destination_port"], errors="raise"
    )
    df["bytes_sent"] = pd.to_numeric(
        df["bytes_sent"], errors="raise"
    )

    if not df["destination_port"].between(1, 65535).all():
        raise ValueError("Destination ports must be between 1 and 65535.")

    if (df["bytes_sent"] < 0).any():
        raise ValueError("bytes_sent cannot be negative.")

    return df


def detect_port_scans(events):
    """Find source/destination pairs contacting 10+ ports within 5 minutes."""
    findings = []

    for (source, destination), group in events.groupby(
        ["source_ip", "destination_ip"]
    ):
        group = group.sort_values("timestamp").reset_index(drop=True)
        left = 0

        for right in range(len(group)):
            while (
                group.loc[right, "timestamp"]
                - group.loc[left, "timestamp"]
            ).total_seconds() > WINDOW_SECONDS:
                left += 1

            window = group.iloc[left:right + 1]
            ports = sorted(window["destination_port"].unique())

            if len(ports) >= PORT_THRESHOLD:
                findings.append({
                    "source_ip": source,
                    "destination_ip": destination,
                    "unique_ports": len(ports),
                    "ports": ", ".join(map(str, ports)),
                    "first_seen": window["timestamp"].iloc[0],
                    "last_seen": window["timestamp"].iloc[-1],
                    "reason": (
                        f"{len(ports)} distinct ports contacted "
                        f"within {WINDOW_SECONDS} seconds"
                    ),
                })
                break

    return pd.DataFrame(findings)


def detect_high_transfers(events):
    """Find individual events meeting the high-transfer threshold."""
    findings = events.loc[
        events["bytes_sent"] >= TRANSFER_THRESHOLD
    ].copy()

    findings["reason"] = (
        f"Single event sent at least {TRANSFER_THRESHOLD:,} bytes"
    )

    return findings


def main():
    events = load_events()

    scans = detect_port_scans(events)
    transfers = detect_high_transfers(events)

    print("=" * 60)
    print("NETWORK THREAT HUNTING — CASE NTH-001")
    print("=" * 60)
    print(f"Events analysed: {len(events)}")

    print(f"\nPotential port-scan findings: {len(scans)}")
    if scans.empty:
        print("No potential port scans detected.")
    else:
        print(scans.to_string(index=False))

    print(f"\nHigh-transfer events: {len(transfers)}")
    if transfers.empty:
        print("No high-transfer events detected.")
    else:
        columns = [
            "timestamp", "source_ip", "destination_ip",
            "destination_port", "bytes_sent", "reason"
        ]
        print(transfers[columns].to_string(index=False))

    print("\nAssessment:")
    print("These are investigation leads, not proof of malicious activity.")
    print("The dataset is synthetic; no live network or SIEM was queried.")


if __name__ == "__main__":
    main()
