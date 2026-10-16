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
