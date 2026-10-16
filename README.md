# network-threat-hunting
SOC project analyzing synthetic network traffic for suspicious behaviour using python.

## NTH-001 Investigation Results

The Python analysis of the synthetic network dataset identified:

- One potential port-scan pattern involving 10 distinct destination ports
  within nine seconds.
- Three high-transfer events totalling 2,910,000 bytes.
- Four passing automated tests covering the configured detection rules.

These results are investigation leads, not proof of malicious activity.
The dataset is synthetic; no live network or SIEM was queried.

**Investigation report:** [`reports/NTH-001-investigation-report.md`](reports/NTH-001-investigation-report.md)

**Run the analysis:**
```bash
python src/hunt_network.py
```

**Run the tests:**
```bash
python -m unittest discover -s tests -v
```

## Structured Alert Export

The hunting script exports findings to `output/alerts.csv`. Each row
includes the finding type, source and destination IPs, relevant event
details, provisional severity, investigation reason, and recommended
next actions.

Run the hunt from the repository root with:

```bash
python src/hunt_network.py
```

The output is generated from synthetic training data. Alerts are
investigation leads, not proof of malicious activity. No live network
or SIEM was queried.

## False-Positive Analysis and Detection Tuning

The potential port-scan rule uses a 60-second rolling window and requires
at least 10 distinct destination ports for the same source/destination pair.
This reduces alerts for slower connections spread over a longer period,
but may miss slower scans. It is a configurable training threshold, not a
universal security standard.

High-transfer events are flagged individually at 900,000 bytes or more.
A legitimate software update, backup, or approved transfer could meet this
threshold. Analysts should verify the application, asset owner, business
purpose, destination, and surrounding activity before escalating.

The tests cover both sides of the 60-second port-scan boundary. All data
remains synthetic; these tests do not validate the rule against live traffic.

## Cumulative Transfer Detection

The hunt also evaluates total bytes sent by the same source/destination
pair within a rolling 60-second window. It creates a provisional finding
when the total reaches 2,500,000 bytes, even if no individual event reaches
the existing 900,000-byte high-transfer threshold.

This is a training threshold, not a universal security standard. Repeated
transfers can be legitimate. Analysts should validate the asset, application,
business purpose, destination, and surrounding activity. The synthetic tests
check an above-threshold total, a below-threshold total, and events spread
outside the window. They do not validate effectiveness against live traffic.

## Alert Correlation and Case Management

The correlation layer groups alerts sharing the same source and destination
IP addresses when their timestamps fall within the configured correlation
window (60 seconds by default). Alerts outside that window form separate
cases. Case IDs are assigned in first-seen order for each analysis run.

Outputs:
- `output/alerts.csv`: original detection alerts.
- `output/correlated-alerts.csv`: each alert with an alert ID, case ID,
  and correlation explanation.
- `output/cases.csv`: one summary row per investigation case.

**Important distinction:** a network event is an observed connection or
transfer; an alert is a detection generated from evidence; a case groups
related alerts for investigation. One event may contribute to more than one
alert. Therefore, alert counts are not equivalent to event counts.

For this synthetic dataset, five alerts are grouped into two cases:
one port-scan case and one high-transfer case. The transfer case contains
three individual high-transfer alerts and one cumulative alert. These overlap
and must not be counted as four separate transfers or summed as independent
byte totals.

Correlation is a triage aid, not proof of malicious activity. The grouping
uses source/destination IPs and time only; it does not establish causality
or asset identity. Severity remains provisional. No live network or SIEM
was queried.
