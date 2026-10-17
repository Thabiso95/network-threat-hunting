# Sample Investigation Outcome Report

## Purpose and scope

This training report demonstrates two possible endings for case
`NTH-001-CASE-002`. The outcomes are alternatives, not simultaneous findings.

**Environment:** Synthetic training dataset  
**Live investigation performed:** No  
**Real application or endpoint evidence collected:** No

The scenario outcomes below are hypothetical. They have not been independently
verified and must not be represented as actual findings from the supplied CSV.

## Common starting point

The synthetic network dataset contains three high-transfer events from
`192.0.2.70` to `198.51.100.90`, totalling 2,910,000 bytes over approximately
10 seconds. The configured cumulative-transfer threshold is exceeded.

This is a detection signal, not proof of data theft. The original dataset does
not establish destination ownership, business authorisation, transferred
content, or malicious intent.

The actual training case remains **Investigating / Pending** unless an
authorised case update is made using verified evidence and the applicable
case-handling procedure.

---

## Outcome A — Hypothetical evidence supports benign closure

### Hypothetical evidence

For this alternative scenario only, assume the analyst obtains and validates:

- An approved job configuration identifying the source host and destination.
- Execution records showing the job ran at the relevant time.
- Independent network records correlating the connection with the job.
- Transfer records that reasonably reconcile the reported byte counts,
  including any documented rounding or measurement differences.
- Confirmation from the authorised service owner that the transfer was expected.
- No unresolved material contradictions after the relevant checks.

These are assumed scenario facts, not findings contained in the original dataset.

### Analyst assessment

The evidence supports the explanation that the observed transfer was generated
by an authorised scheduled job. The detection was useful because it prompted
validation, but the threshold alone did not establish malicious activity.

### Recommended disposition

**Potential disposition:** `Benign`  
**Potential status:** `Closed`, subject to the organisation's procedure.

Before closure, the analyst should record the evidence references, sources,
review timestamps, validation steps, rationale and any residual limitations.
Closure should be performed through the approved case-management workflow.

### Example closure rationale

> Reviewed the approved job configuration, execution records and independent
> network evidence. The source, destination and execution timing were correlated;
> transfer-volume differences were reconciled using the documented measurement
> method. The authorised service owner confirmed the expected activity. No
> unresolved material contradictions were identified in the reviewed evidence.
> The activity is assessed as benign under the applicable case-handling procedure.

Use this wording only if the stated evidence has actually been collected and
reviewed in the scenario being documented.

---

## Outcome B — Evidence remains incomplete or contradictory

### Hypothetical evidence

For this alternative scenario, assume one or more material gaps remain:

- The source host cannot be reliably linked to the scheduled job; or
- Transfer records do not reconcile with the network observations; or
- The job's authorisation or purpose cannot be verified; or
- Available logs conflict, or relevant telemetry is unavailable.

These are alternative scenario conditions, not verified findings from the
original dataset.

### Analyst assessment

The scheduled job may be a plausible explanation, but the available evidence
does not sufficiently establish that it accounts for the detected traffic.
Missing evidence is not proof of malicious activity; equally, an unverified
benign explanation is not sufficient grounds for closure.

### Recommended disposition

**Status:** `Investigating` or escalated according to the applicable procedure.  
**Disposition:** `Pending` until evidence supports a defensible conclusion.

The analyst should document the unresolved questions, request relevant records,
preserve available evidence according to policy, and escalate when warranted
by risk, policy or investigation requirements.

### Example investigation note

> A scheduled job has been proposed as a possible explanation for the transfer.
> The relationship between the job and the observed network events remains
> unverified because material evidence gaps remain. Authorisation, source and
> transfer details require further validation. Malicious exfiltration is
> unconfirmed. The case remains open pending additional evidence and review.

---

## Decision criteria

| Question | Supports benign closure | Supports continued investigation |
|---|---|---|
| Is the source host matched? | Reliably correlated | Unknown or conflicting |
| Is the destination authorised? | Verified for this activity | Only generally recognised or unverified |
| Does the job explain the timing? | Execution records corroborate it | Timing alone or incomplete records |
| Is transfer volume reconciled? | Differences are explained and documented | Material discrepancy remains |
| Is independent correlation available? | Reliable records link job and traffic | Link remains unproven |
| Are material contradictions resolved? | Yes, within the scope reviewed | No, or evidence remains unavailable |

No single row automatically determines the outcome. Assess the evidence as a
whole, document limitations, and follow the applicable incident-management
and case-closure procedures.

## Analyst learning points

1. Detection is not the same as confirmation.
2. Correlation is stronger when supported by independent, reliable records.
3. A plausible explanation must be tested against the observed activity.
4. Evidence gaps and contradictory records must be documented explicitly.
5. Benign closure requires a defensible rationale, not merely an absence of proof.
6. Training assumptions must never be presented as collected evidence.
