"""Case lifecycle, analyst disposition, and append-only audit logging."""

from pathlib import Path
from datetime import datetime, timezone
import argparse
import pandas as pd

REGISTER = Path("output/case-register.csv")
AUDIT_LOG = Path("output/case-audit-log.csv")

STATUSES = {"Open", "Investigating", "Escalated", "Closed"}
DISPOSITIONS = {
    "Pending", "Benign", "Suspicious",
    "Confirmed Malicious", "Inconclusive",
}

REGISTER_COLUMNS = [
    "case_id", "source_ip", "destination_ip", "priority_score",
    "priority", "status", "disposition", "evidence_reviewed",
    "analyst_notes", "created_at", "updated_at",
]

AUDIT_COLUMNS = [
    "audit_id", "timestamp", "case_id", "analyst",
    "action", "previous_status", "new_status",
    "previous_disposition", "new_disposition", "reason",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_csv(path, columns):
    if not path.exists():
        return pd.DataFrame(columns=columns)
    return pd.read_csv(path, keep_default_na=False)


def _write_csv(df, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def initialize_register(prioritized, register_path=REGISTER,
                        audit_path=AUDIT_LOG):
    """Add newly prioritised cases without overwriting analyst decisions."""
    required = {
        "case_id", "source_ip", "destination_ip",
        "priority_score", "priority",
    }
    missing = required - set(prioritized.columns)
    if missing:
        raise ValueError(
            f"Prioritised input missing columns: {sorted(missing)}"
        )

    register = _read_csv(register_path, REGISTER_COLUMNS)
    audit = _read_csv(audit_path, AUDIT_COLUMNS)

    if not register.empty and register["case_id"].duplicated().any():
        raise ValueError("Existing register contains duplicate case IDs.")

    existing = set(register["case_id"].astype(str))
    timestamp = utc_now()
    new_rows = []
    audit_rows = []

    for _, case in prioritized.iterrows():
        case_id = str(case["case_id"])
        if not case_id or case_id == "nan":
            raise ValueError("A case ID is missing.")
        if case_id in existing:
            continue

        new_rows.append({
            "case_id": case_id,
            "source_ip": case["source_ip"],
            "destination_ip": case["destination_ip"],
            "priority_score": case["priority_score"],
            "priority": case["priority"],
            "status": "Open",
            "disposition": "Pending",
            "evidence_reviewed": "",
            "analyst_notes": "",
            "created_at": timestamp,
            "updated_at": timestamp,
        })

        audit_rows.append({
            "audit_id": "",
            "timestamp": timestamp,
            "case_id": case_id,
            "analyst": "System",
            "action": "CASE_REGISTERED",
            "previous_status": "",
            "new_status": "Open",
            "previous_disposition": "",
            "new_disposition": "Pending",
            "reason": "New prioritised case added to the case register.",
        })
        existing.add(case_id)

    if new_rows:
        register = pd.concat(
            [register, pd.DataFrame(new_rows)],
            ignore_index=True,
        )

    if audit_rows:
        audit = pd.concat(
            [audit, pd.DataFrame(audit_rows)],
            ignore_index=True,
        )

    if not audit.empty:
        audit["audit_id"] = [
            f"NTH-AUDIT-{i:05d}"
            for i in range(1, len(audit) + 1)
        ]

    _write_csv(register[REGISTER_COLUMNS], register_path)
    _write_csv(audit[AUDIT_COLUMNS], audit_path)

    return register, audit


def update_case(case_id, register_path=REGISTER, audit_path=AUDIT_LOG,
                analyst="Analyst", status=None, disposition=None,
                evidence_reviewed=None, analyst_notes=None, reason=None):
    """Update one case and record the change in the audit log."""
    if not reason or not reason.strip():
        raise ValueError("A non-empty reason is required for every update.")
    if not analyst or not analyst.strip():
        raise ValueError("Analyst name must not be empty.")

    if status is not None and status not in STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if disposition is not None and disposition not in DISPOSITIONS:
        raise ValueError(f"Invalid disposition: {disposition}")

    register = _read_csv(register_path, REGISTER_COLUMNS)
    audit = _read_csv(audit_path, AUDIT_COLUMNS)

    matches = register.index[register["case_id"].astype(str) == str(case_id)]
    if len(matches) != 1:
        raise ValueError(f"Expected one registered case for {case_id!r}.")

    idx = matches[0]
    old = register.loc[idx].copy()

    new_status = status if status is not None else old["status"]
    new_disposition = (
        disposition if disposition is not None else old["disposition"]
    )
    new_evidence = (
        evidence_reviewed
        if evidence_reviewed is not None
        else old["evidence_reviewed"]
    )
    new_notes = (
        analyst_notes if analyst_notes is not None else old["analyst_notes"]
    )

    if new_status == "Closed":
        if new_disposition == "Pending":
            raise ValueError(
                "A case cannot be closed with Pending disposition."
            )
        if not str(new_evidence).strip():
            raise ValueError(
                "Record the evidence reviewed before closing a case."
            )
        if not str(new_notes).strip():
            raise ValueError(
                "Record analyst notes before closing a case."
            )

    timestamp = utc_now()
    register.loc[idx, "status"] = new_status
    register.loc[idx, "disposition"] = new_disposition
    register.loc[idx, "evidence_reviewed"] = new_evidence
    register.loc[idx, "analyst_notes"] = new_notes
    register.loc[idx, "updated_at"] = timestamp

    action = (
        "CASE_UPDATED"
        if (
            new_status != old["status"]
            or new_disposition != old["disposition"]
            or new_evidence != old["evidence_reviewed"]
            or new_notes != old["analyst_notes"]
        )
        else "CASE_REVIEW_NOTE_ADDED"
    )

    audit_row = {
        "audit_id": f"NTH-AUDIT-{len(audit) + 1:05d}",
        "timestamp": timestamp,
        "case_id": str(case_id),
        "analyst": analyst.strip(),
        "action": action,
        "previous_status": old["status"],
        "new_status": new_status,
        "previous_disposition": old["disposition"],
        "new_disposition": new_disposition,
        "reason": reason.strip(),
    }

    audit = pd.concat(
        [audit, pd.DataFrame([audit_row])],
        ignore_index=True,
    )

    _write_csv(register[REGISTER_COLUMNS], register_path)
    _write_csv(audit[AUDIT_COLUMNS], audit_path)

    return register.loc[idx], audit_row


def main():
    parser = argparse.ArgumentParser(
        description="Manage network-hunt case lifecycle and disposition."
    )
    parser.add_argument("--case-id")
    parser.add_argument("--analyst", default="Analyst")
    parser.add_argument("--status", choices=sorted(STATUSES))
    parser.add_argument("--disposition", choices=sorted(DISPOSITIONS))
    parser.add_argument("--evidence-reviewed")
    parser.add_argument("--notes")
    parser.add_argument("--reason")
    args = parser.parse_args()

    if not args.case_id:
        source = Path("output/prioritized-cases.csv")
        if not source.exists():
            raise FileNotFoundError(
                "Run src/prioritize_cases.py first to create "
                "output/prioritized-cases.csv."
            )
        prioritized = pd.read_csv(source)
        register, audit = initialize_register(prioritized)
        print(f"Cases in register: {len(register)}")
        print(f"Audit entries: {len(audit)}")
        print(f"Register: {REGISTER}")
        print(f"Audit log: {AUDIT_LOG}")
        print("Existing analyst decisions are preserved.")
        return

    if not args.reason:
        parser.error("--reason is required when updating a case")

    row, entry = update_case(
        case_id=args.case_id,
        analyst=args.analyst,
        status=args.status,
        disposition=args.disposition,
        evidence_reviewed=args.evidence_reviewed,
        analyst_notes=args.notes,
        reason=args.reason,
    )
    print(f"Updated case: {row['case_id']}")
    print(f"Status: {row['status']}")
    print(f"Disposition: {row['disposition']}")
    print(f"Audit entry: {entry['audit_id']}")
    print(f"Register: {REGISTER}")
    print(f"Audit log: {AUDIT_LOG}")


if __name__ == "__main__":
    main()
