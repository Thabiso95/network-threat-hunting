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
