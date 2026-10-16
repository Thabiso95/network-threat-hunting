Network Threat Hunting — Evidence

Case ID

NTH-001

Dataset

Synthetic network connection records created for cybersecurity training.

Purpose

The dataset will be used to practise identifying suspicious network behaviour, including potential port scanning and unusual connection patterns.

Data Handling

- No real network traffic or personal data is included.
- IP addresses and activity patterns are provided for controlled analysis.
- Findings are investigative leads, not confirmation of malicious activity.

Limitations

The dataset is small and synthetic. It does not represent the full complexity of a production network, and detections must not be treated as validated against real-world traffic.

## Dataset Documentation

### Purpose

`network-traffic.csv` is a synthetic training dataset for the
Network Threat Hunting project, case NTH-001. It allows the detection
script and automated tests to be exercised without using real
organisational network traffic.

### Dataset fields

| Field | Description |
|---|---|
| `timestamp` | Time the synthetic connection event occurred |
| `source_ip` | IP address initiating the connection |
| `destination_ip` | Destination IP address |
| `destination_port` | Destination service port |
| `protocol` | Network protocol recorded for the event |
| `connection_state` | Recorded connection state |
| `bytes_sent` | Number of bytes sent in that event |

### Patterns intentionally included

- **Potential port scan:** source `192.0.2.50` contacts multiple ports
  on destination `198.51.100.60` in a short period. The current rule
  looks for at least 10 distinct destination ports within 60 seconds.
- **High-transfer events:** source `192.0.2.70` sends three individual
  events of 950,000, 970,000, and 990,000 bytes to destination
  `198.51.100.90` on TCP port 8080. Each event exceeds the configured
  900,000-byte threshold.

The IP addresses are from documentation-only address ranges reserved
for examples. They do not identify the real systems involved in an
incident.

### Limitations

- All records are synthetic and are not evidence of a real incident.
- The patterns were deliberately included to test expected detection
  behaviour; they do not represent a statistically representative
  baseline of normal network activity.
- A port scan can be legitimate, and a large transfer can be an
  authorised backup, update, or application transfer.
- The current high-transfer rule evaluates individual events. It does
  not yet detect cumulative transfer volume across multiple smaller
  events.
- The configured thresholds are training choices, not universal
  security standards.
- No live network, production telemetry, or SIEM was queried.

### Reproducing the analysis

From the repository root, run:

```bash
python src/hunt_network.py
python -m unittest discover -s tests -v
```

The analysis writes structured findings to `output/alerts.csv`.
Automated tests check the documented detection behaviour. Passing
synthetic tests does not establish detection effectiveness on real traffic.

### Cumulative transfer detection

The script also evaluates the total bytes sent by each source/destination
pair over a rolling 60-second window. The configured training threshold is
2,500,000 bytes. The current dataset's three high-transfer events can meet
this aggregate threshold as well as triggering individual-event alerts.
These are separate detection signals and may overlap; they must not be
treated as independent proof of malicious activity.

The synthetic dataset does not yet represent a broad normal-traffic baseline.
Tests use additional synthetic events to verify cumulative detection and
non-detection scenarios.
