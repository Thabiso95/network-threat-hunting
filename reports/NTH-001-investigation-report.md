# Network Threat Hunting Investigation Report

## Case Information

- **Case ID:** NTH-001
- **Investigation type:** Network traffic analysis
- **Dataset:** `evidence/network-traffic.csv`
- **Dataset classification:** Synthetic training data
- **Status:** Initial investigation completed

## 1. Objective

Identify network activity patterns that may warrant further investigation,
focusing on potential port scanning and unusually large individual transfers.

## 2. Methodology

A Python script using pandas analysed the supplied CSV dataset.

Detection rules:
- **Potential port scan:** At least 10 distinct destination ports contacted
  by the same source and destination within a five-minute window.
- **High-transfer event:** An individual event with at least 900,000 bytes sent.

Four automated tests were executed to validate detection behaviour.

## 3. Findings

### Finding 1: Potential port scanning

- **Source IP:** `192.0.2.50`
- **Destination IP:** `198.51.100.60`
- **Distinct ports in the detected window:** 10
- **Observed interval:** 2026-10-15 09:05:00–09:05:09 UTC
- **Detection basis:** Ten distinct destination ports were contacted within
  the configured five-minute window.

**Assessment:** The pattern is consistent with possible port scanning.
The dataset alone does not establish intent or confirm malicious activity.

### Finding 2: High-transfer events

- **Source IP:** `192.0.2.70`
- **Destination IP:** `198.51.100.90`
- **Destination port:** TCP/8080
- **Events detected:** 3
- **Bytes per event:** 950,000; 970,000; 990,000
- **Combined bytes across these events:** 2,910,000
- **Observed interval:** 2026-10-15 09:06:30–09:06:40 UTC

**Assessment:** The repeated large transfers warrant contextual review.
Large transfers alone do not prove data exfiltration or other malicious behaviour.

## 4. Validation

Four automated tests passed:

1. Detects a sequence involving ten distinct ports.
2. Does not flag a sequence involving fewer than ten ports.
3. Detects an individual transfer meeting the byte threshold.
4. Does not flag an ordinary transfer below the threshold.

These tests validate selected scenarios, not every possible traffic pattern.

## 5. Limitations

- The dataset is synthetic and small.
- No live network traffic was collected or queried.
- No live Microsoft Sentinel or other SIEM execution was performed.
- No packet payloads, asset criticality, user context, or baseline traffic were
  available for correlation.
- The detections are investigation leads, not confirmed incidents.

## 6. Recommended Follow-up

For a real environment, validate the source and destination assets, review
connection outcomes and surrounding events, compare transfer volumes against
normal baselines, and correlate findings with endpoint and identity telemetry.

## 7. Conclusion

The script identified one potential port-scan pattern and three high-transfer
events in the synthetic dataset. All four automated tests passed. Further
context would be required before classifying either pattern as malicious.

## 8. Initial Severity and Triage

Severity labels in the script are provisional training classifications,
not confirmed incident ratings.

### Potential port-scan pattern

- **Initial priority:** Medium — provisional
- **Reason:** Rapid contact with multiple destination ports may indicate
  reconnaissance, but legitimate scanning and other explanations are possible.
- **Recommended checks:** Review connection states and firewall records;
  identify the source and destination assets; correlate with other alerts;
  determine whether any subsequent connections succeeded.

### High-transfer events

- **Initial priority:** Medium — provisional
- **Reason:** Three individual events exceeded the configured byte threshold.
  Large transfers can be legitimate, and volume alone does not establish
  data exfiltration.
- **Recommended checks:** Identify the application and asset owner; compare
  traffic against normal baselines; review the destination and surrounding
  connections; confirm whether the transfer was expected and authorized.

### Escalation considerations

Consider escalating according to the organization's incident-response
procedure if corroborating evidence indicates unauthorized scanning,
unexpected access, sensitive data movement, or activity involving a critical
asset. Record the evidence and reasoning. Do not automatically declare an
incident based solely on these synthetic findings.

## Structured Alert Export and Validation

The detection script writes structured findings to `output/alerts.csv`.
The export includes finding type, source IP, destination IP, destination
port where applicable, timestamp, event count, bytes sent where applicable,
provisional severity, reason, and recommended actions.

Validation results:
- Five automated unit tests passed.
- The synthetic dataset contained 21 events.
- Four findings were generated: one potential port-scan finding and three
  high-transfer event findings.
- CSV export was verified by reading the generated file back into pandas.

The findings remain provisional. The high-transfer events do not by
themselves establish data exfiltration, and the port-scan finding does
not establish malicious intent. Further investigation and asset/context
validation would be required. No live network or SIEM was queried.

## False-Positive Analysis and Detection Tuning

The port-scan rolling window was reduced from 300 seconds to 60 seconds.
The rule still requires at least 10 distinct destination ports for the same
source/destination pair. Automated tests verify that ten ports spanning
54 seconds trigger a finding, while ten ports spread across 63 seconds do
not trigger a finding under the 60-second rule.

This tuning reduces findings for slower-spread connections but may miss
slower scans. The threshold should be adjusted to the environment and
validated against representative baseline traffic before operational use.

High-transfer alerts may represent legitimate backups, software distribution,
or other approved transfers. Validation should include the asset owner,
application, business purpose, destination, and surrounding connections.
No alert alone confirms malicious activity. The dataset and test cases are
synthetic; no live network or SIEM was queried.

## Cumulative Transfer Detection

A second transfer rule evaluates cumulative bytes sent by the same
source/destination pair within a rolling 60-second window. The provisional
training threshold is 2,500,000 bytes. This can identify a series of smaller
transfers that would not individually meet the 900,000-byte event threshold.

The rule emits one aggregate finding per source/destination pair per hunt.
It may overlap with individual high-transfer alerts when the same activity
meets both rules. This overlap is a known alert-deduplication consideration,
not independent confirmation of malicious activity.

Automated synthetic tests cover an above-threshold total, a below-threshold
total, and events spread beyond the window. Live traffic and SIEM performance
have not been evaluated.
