# Evidence Collection Checklist

## Case details

- **Case ID:** NTH-001-CASE-002
- **Current status:** Investigating
- **Current disposition:** Pending
- **Priority:** High (heuristic triage score, not a probability of compromise)
- **Dataset:** `evidence/network-traffic.csv`
- **Dataset type:** Synthetic training data
- **Live environment queried:** No
- **Endpoint telemetry available:** No, according to the scenario

## Investigation objective

Determine whether the observed high-volume transfer has an authorised,
expected explanation or whether additional evidence supports escalation.
Do not label the activity as exfiltration solely because a byte threshold
was exceeded.

## Evidence collection checklist

Record each item as **Not requested**, **Requested**, **Received**, **Unavailable**,
or **Not applicable**. Add the source, timestamp, analyst and findings when
evidence is received. Do not mark evidence as collected before reviewing it.

### 1. Validate the existing network evidence

- [ ] Review the original synthetic events and their timestamps.
- [ ] Confirm source, destination, destination port, protocol and byte counts.
- [ ] Verify the cumulative-transfer alert against the underlying events.
- [ ] Confirm which individual alerts overlap with the cumulative alert.
- [ ] Check the applicable time window and detection thresholds.
- [ ] Record what the data establishes and what it cannot establish.

**Known from the supplied synthetic dataset:** three high-transfer events from
`192.0.2.70` to `198.51.100.90` total 2,910,000 bytes over approximately
10 seconds. These are documentation-only IP addresses.

**Important limitation:** the original CSV does not establish the contents of
the transfer, destination ownership, business authorisation or malicious intent.

### 2. Validate destination ownership and purpose

- [ ] Identify the destination using an approved internal inventory or
      authoritative asset/service records.
- [ ] Determine the service owner and intended application purpose.
- [ ] Check relevant threat-intelligence sources, documenting source and date.
- [ ] Verify whether the destination and port are expected for this workload.
- [ ] Record any conflicting or inconclusive results.

Do not infer that a destination is malicious merely because it is unfamiliar
or absent from an inventory.

### 3. Establish business authorisation

- [ ] Ask the service or data owner whether the transfer was expected.
- [ ] Check approved change requests, jobs, maintenance windows or transfer records.
- [ ] Establish the expected source, destination, volume, timing and purpose.
- [ ] Record who validated the explanation and what evidence supports it.
- [ ] Treat an unverified explanation as unresolved, not as proof of innocence.

### 4. Request corroborating network and application evidence

- [ ] Obtain relevant firewall, proxy, DNS, flow or network-security logs if available.
- [ ] Check connection duration, frequency and surrounding traffic.
- [ ] Seek application or transfer-service logs that identify the operation.
- [ ] Determine whether transferred content or data classification can be
      established through authorised logs or records.
- [ ] Preserve timestamps and time-zone information when correlating sources.

Byte counts alone do not identify the transferred data or prove that it left
an organisation's authorised boundary.

### 5. Request endpoint evidence

- [ ] Identify the source endpoint and relevant user or service account.
- [ ] Request available EDR, process-creation and command-line telemetry.
- [ ] Correlate the connection with the responsible process and parent process.
- [ ] Check relevant authentication events and endpoint alerts.
- [ ] Document unavailable telemetry and any resulting investigation limitations.

Do not invent endpoint findings when endpoint telemetry has not been provided.

### 6. Validate the reported repeated activity

- [ ] Obtain the underlying events for any reported repeat occurrence.
- [ ] Compare timestamps, endpoints, destination, ports and transfer volumes.
- [ ] Distinguish independently observed evidence from scenario-reported claims.
- [ ] Update the assessment only when supporting evidence has been reviewed.

The scenario reports repeated similar activity, but the original CSV alone does
not independently establish those additional occurrences.

### 7. Document, preserve and escalate

- [ ] Record each evidence request, source, response and review timestamp.
- [ ] Preserve relevant records according to applicable evidence-handling policy.
- [ ] Document alternative benign explanations and evidence for or against them.
- [ ] Record unresolved questions, evidence gaps and next actions.
- [ ] Escalate through the appropriate procedure if risk or policy warrants it.
- [ ] Keep the case open while material questions remain unresolved.
- [ ] Change disposition only when the available evidence supports that decision.

## Assessment guardrails

- A detection threshold is a triage signal, not proof of malicious activity.
- Correlated alerts may describe the same underlying transfer and should not
  automatically be counted as independent incidents or separate transferred data.
- Missing evidence is not evidence of maliciousness.
- Do not close the case as benign, suspicious or confirmed malicious without
  documenting the basis for that disposition.

## Current assessment

**Status:** Investigating  
**Disposition:** Pending

The synthetic transfer pattern exceeds the configured cumulative threshold.
Destination authorisation and application purpose remain unverified. Endpoint
telemetry is unavailable. Malicious exfiltration remains unconfirmed.

**Next action:** request destination ownership and authorisation records, relevant
network/application logs, and available endpoint telemetry. Review the evidence
before changing the case disposition.

## Analyst evidence log

Add one entry per evidence item:

| Field | Record |
|---|---|
| Evidence reference | |
| Requested from / source | |
| Request and review timestamps | |
| Collection status | |
| Relevant findings | |
| Limitations / integrity notes | |
| Analyst | |
| Next action | |
