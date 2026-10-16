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
