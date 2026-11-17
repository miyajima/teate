"""Cycle comparisons use the full private ledger, never the bounded display page."""

from __future__ import annotations

import json

from .model import TeateError, timestamp, utcnow

STATUSES = {"affected", "proposed", "testing", "awaiting_deployment", "blocked",
            "resolved", "accepted_risk"}


def changes(ledger) -> dict:
    """Caller holds a write transaction through packet creation and persistence."""
    if not ledger.db.in_transaction:
        raise TeateError("cycle_comparison_requires_transaction")
    current = {f["id"]: f["effective_status"] for f in ledger.findings()}
    row = ledger.db.execute("SELECT observed_at,statuses FROM agent_cycle_baseline WHERE id=1").fetchone()
    previous, since = None, None
    if row is not None:
        try:
            value = json.loads(row["statuses"])
            timestamp(row["observed_at"])
            if not isinstance(value, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) or v not in STATUSES
                for k, v in value.items()
            ):
                raise ValueError("invalid baseline")
            previous, since = value, row["observed_at"]
        except (ValueError, TypeError, TeateError):
            pass
    observed = utcnow()
    result = {"status": "baseline_unavailable", "since": since, "observed_at": observed,
              "new": None, "continuing": None, "resolved_new": None, "missing": None}
    if previous is not None:
        active = {k for k, v in current.items() if v not in {"resolved", "accepted_risk"}}
        old_active = {k for k, v in previous.items() if v not in {"resolved", "accepted_risk"}}
        result.update(status="compared", new=len(active-old_active), continuing=len(active & old_active),
                      resolved_new=sum(v == "resolved" and previous.get(k) != "resolved"
                                       for k, v in current.items()),
                      missing=len(previous.keys()-current.keys()))
    ledger.db.execute(
        "INSERT OR REPLACE INTO agent_cycle_baseline(id,observed_at,statuses) VALUES(1,?,?)",
        (observed, json.dumps(current, sort_keys=True)),
    )
    return result
