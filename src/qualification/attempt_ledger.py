"""An append-only, crash-surviving ledger for one-shot attempts.

WHY THIS EXISTS
    A launch budget that is a literal in a report is not a budget.  Regenerating
    the report restores it.  This module makes the budget a *derived* quantity:

        remaining = supervisor_authorisation - consuming records in the ledger

WHY THE CHAIN
    Every record carries the digest of the record before it, so truncating the
    file or editing a middle record is detectable from the head alone.  Without
    it, "append-only" is a comment rather than a property.

WHY BUDGET IS CONSUMED *BEFORE* THE ACTION
    A consuming event is written, flushed and fsynced before the action it
    describes.  A crash between the two therefore consumes the attempt rather
    than restoring it.  Consuming after the outcome is known would make a crash
    indistinguishable from a free retry.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone

GENESIS = "0" * 64

#: Events that consume budget.  A RESERVED record that never reaches one of
#: these does not consume, and is reported explicitly rather than dropped.
CONSUMING_EVENTS = ("LAUNCH_STARTED",)

EVENTS = ("RESERVED", "PRELAUNCH_PASS", "LAUNCH_STARTED", "PROCESS_RETURNED",
          "WER_CLASSIFIED", "FINAL_OUTCOME")


def record_digest(record):
    """Digest of a record's contents, excluding its own digest field."""
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AttemptLedger:
    """An append-only ledger file.  Every write is flushed and fsynced."""

    def __init__(self, path):
        self.path = path

    # -- reading ----------------------------------------------------------
    def read(self):
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return out

    def verify_chain(self):
        """Recompute the whole chain and report the FIRST break."""
        prev = GENESIS
        for i, rec in enumerate(self.read()):
            if rec.get("previous_record_sha256") != prev:
                return {"intact": False, "broken_at_sequence": rec.get("sequence", i),
                        "why": "previous_record_sha256 does not match the "
                               "preceding record"}
            if rec.get("record_sha256") != record_digest(rec):
                return {"intact": False, "broken_at_sequence": rec.get("sequence", i),
                        "why": "the record's own digest does not match its contents"}
            prev = rec["record_sha256"]
        return {"intact": True, "n_records": len(self.read()), "head": prev}

    # -- writing ----------------------------------------------------------
    def append(self, event, attempt_uuid=None, **fields):
        if event not in EVENTS:
            raise ValueError("unknown event %r; allowed: %s" % (event, EVENTS))
        records = self.read()
        prev = records[-1]["record_sha256"] if records else GENESIS
        rec = {
            "sequence": len(records),
            "attempt_uuid": attempt_uuid or str(uuid.uuid4()),
            "previous_record_sha256": prev,
            "event": event,
            "utc": utc_now(),
        }
        rec.update(fields)
        rec["record_sha256"] = record_digest(rec)

        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return rec

    # -- derived budget ---------------------------------------------------
    def reserve(self, attempt_uuid=None, **fields):
        """Reserving does NOT consume budget."""
        return self.append("RESERVED", attempt_uuid=attempt_uuid, **fields)

    def consume(self, attempt_uuid, **fields):
        """Append a consuming event.  Refuses to consume the same attempt twice."""
        for rec in self.read():
            if (rec.get("attempt_uuid") == attempt_uuid
                    and rec.get("event") in CONSUMING_EVENTS):
                return None                 # already consumed; no silent retry
        return self.append("LAUNCH_STARTED", attempt_uuid=attempt_uuid, **fields)

    def derive_budget(self, authorised):
        """remaining = authorised - consuming records.  Never a literal."""
        records = self.read()
        consumed = [r for r in records if r.get("event") in CONSUMING_EVENTS]
        consumed_uuids = {r["attempt_uuid"] for r in consumed}
        reserved = [r for r in records if r.get("event") == "RESERVED"]
        never_launched = [r for r in reserved
                          if r["attempt_uuid"] not in consumed_uuids]
        return {
            "authorised": int(authorised),
            "derived_spent": len(consumed),
            "derived_remaining": max(0, int(authorised) - len(consumed)),
            "reserved_but_never_launched": [
                {"attempt_uuid": r["attempt_uuid"], "utc": r.get("utc")}
                for r in never_launched],
            "derivation_rule": ("remaining = authorised - the number of consuming "
                                "records. A RESERVED record that never reached a "
                                "consuming event does not consume budget. A "
                                "consuming event consumes regardless of any later "
                                "crash, because it is recorded BEFORE the action."),
            "hardcoded": False,
            "chain": self.verify_chain(),
        }
