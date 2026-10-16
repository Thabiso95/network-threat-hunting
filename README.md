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
