#!/usr/bin/env python3
"""The artifact-backed qualification ledger.

The defect this replaces
------------------------
`k_readiness.py` decided its readiness flags from four strings typed into the
source:

    ev["F_output_dependency_slice"] = "NOT_BUILT"
    ev["G_j3v2_input_expected_harness"] = "NOT_BUILT"
    ev["I_final_package"] = "PARTIAL (H track only)"
    ev["J_adversarial_release_tests"] = "NOT_BUILT"

Those are claims about the world stored as literals. They cannot go stale
because nothing can contradict them, they do not say *which* artifact was
built or *against what*, and a phase that finally built one of them would
have had to edit the literal by hand -- so the file would report whatever the
last editor believed. Every other flag in that tool is derived from a file;
these four were not, and they were the four gating `J3_READY`.

What replaces them
------------------
One ledger. A record is a statement of the form

    for this (source profile, source object SHA, translated object SHA,
              device, runtime, fixture, geometry, test version)
    this STAGE, at this point in time, had this STATUS
    and here is the artifact that says so, with its SHA-256

The key is the whole eight-tuple. A status is never read out of context, and
two facts about different inputs never merge into one.

Stages are independent
----------------------
`HOST_STATIC`, `HOST_NUMERIC`, `ISOLATED_PHYSICAL`, `AUTHENTIC_DISPATCH`,
`COMPLETE_JOB`, `TRANSPORT`, `PRESENTATION`. There is deliberately no
`overall()`: a PASS at `ISOLATED_PHYSICAL` says the kernel ran in isolation
on a device, which says nothing about whether a complete job ran, and a
single aggregate would let one stand in for the other. Ask for the stage you
mean.

Statuses
--------
`NOT_RUN`, `PASS`, `FAIL`, `UNSUPPORTED`, `STALE`. `UNSUPPORTED` and `FAIL`
are different statements: the first says the stage cannot be evaluated for
this key at all (no such geometry on this device, say), the second says it
was evaluated and did not hold.

`STALE` is computed, never typed
--------------------------------
A record whose cited artifact no longer hashes to what the record says is
reported as `STALE` regardless of the status stored in the file. That is the
one property a literal cannot have: the ledger is checked against the bytes
on disk every time it is read, so an artifact that changes underneath a
record invalidates the record instead of leaving a stale PASS standing.

Host-only, stdlib only, read-only on every artifact it cites.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Sequence, Tuple

SCHEMA = "qualification-ledger/1"

#: Independent evidence stages. Order is the order they are usually reached
#: in, and nothing else: it implies no dependency and no aggregation.
STAGES: Tuple[str, ...] = (
    "HOST_STATIC",
    "HOST_NUMERIC",
    "ISOLATED_PHYSICAL",
    "AUTHENTIC_DISPATCH",
    "COMPLETE_JOB",
    "TRANSPORT",
    "PRESENTATION",
)

STATUSES: Tuple[str, ...] = ("NOT_RUN", "PASS", "FAIL", "UNSUPPORTED", "STALE")

#: The eight-tuple that makes a record about one thing and not another.
KEY_FIELDS: Tuple[str, ...] = (
    "source_profile",
    "source_object_sha256",
    "translated_object_sha256",
    "device",
    "runtime",
    "fixture",
    "geometry",
    "test_version",
)

#: The kernel this project is qualifying: one dispatch of the swin<32,false>
#: variant. A record whose profile is not this one is not about J3.
J3_SOURCE_PROFILE = "swin<32,false>"

#: Profiles that belong to a contributory artifact set rather than to this
#: project's chain. A PASS recorded under one of these must never be counted
#: as evidence for J3, however green it is, because it was measured on a
#: different source object under a different fixture.
FINAL_HEAD_PROFILES: Tuple[str, ...] = ("final-head", "astra-final-head")

#: Statuses that let a stage count toward an advance decision.
ADVANCING = ("PASS",)


class LedgerError(Exception):
    """Base class for every ledger failure."""


class LedgerFormatError(LedgerError):
    """The file is malformed."""


class LedgerKeyError(LedgerError):
    """A record or query key is incomplete or names something unknown."""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# key
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Key:
    """The identity a qualification statement is about."""

    source_profile: str
    source_object_sha256: str
    translated_object_sha256: str
    device: str
    runtime: str
    fixture: str
    geometry: str
    test_version: str

    def __post_init__(self):
        for name in KEY_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise LedgerKeyError(
                    f"key field {name!r} must be a non-empty string "
                    f"(got {value!r}); a partially specified key identifies "
                    "nothing, and two half-keys that both default to '' would "
                    "collide")

    def as_tuple(self) -> Tuple[str, ...]:
        return tuple(getattr(self, f) for f in KEY_FIELDS)

    def short(self) -> str:
        """A one-line rendering for reports."""
        return (f"{self.source_profile} "
                f"src={self.source_object_sha256[:12]} "
                f"xlt={self.translated_object_sha256[:12]} "
                f"{self.device}/{self.runtime} {self.fixture} "
                f"{self.geometry} v{self.test_version}")

    def differences(self, other: "Key") -> List[str]:
        """Field names where the two keys disagree.

        Named rather than booleans so a rejection can say which field made it
        a different question -- which is what makes 'a final-head PASS must
        not advance J3' a diagnosable answer instead of a silent miss.
        """
        return [f for f in KEY_FIELDS if getattr(self, f) != getattr(other, f)]

    def is_final_head(self) -> bool:
        return self.source_profile in FINAL_HEAD_PROFILES


def key_from_dict(d: dict) -> Key:
    if not isinstance(d, dict):
        raise LedgerFormatError(f"a key must be an object, got {type(d).__name__}")
    missing = [f for f in KEY_FIELDS if f not in d]
    if missing:
        raise LedgerKeyError(f"key is missing {missing}; all of {KEY_FIELDS} "
                            "are required")
    extra = [k for k in d if k not in KEY_FIELDS]
    if extra:
        raise LedgerKeyError(f"key has unrecognised fields {extra}")
    return Key(**{f: d[f] for f in KEY_FIELDS})


# ---------------------------------------------------------------------------
# record
# ---------------------------------------------------------------------------
@dataclass
class Artifact:
    """One cited piece of evidence and the hash it had when cited."""

    path: str
    sha256: str

    def check(self, root: str = ".") -> str:
        """'OK', 'MISSING', or 'CHANGED'."""
        full = self.path if os.path.isabs(self.path) else os.path.join(root, self.path)
        if not os.path.exists(full):
            return "MISSING"
        return "OK" if sha256_file(full) == self.sha256 else "CHANGED"


@dataclass
class Record:
    key: Key
    stage: str
    status: str
    artifacts: List[Artifact] = field(default_factory=list)
    note: str = ""
    observed_utc: str = ""

    def __post_init__(self):
        if self.stage not in STAGES:
            raise LedgerFormatError(
                f"stage {self.stage!r} is not one of {list(STAGES)}. Stages "
                "are the ledger's schema, not free text.")
        if self.status not in STATUSES:
            raise LedgerFormatError(
                f"status {self.status!r} is not one of {list(STATUSES)}")
        if self.status == "STALE":
            raise LedgerFormatError(
                "STALE is computed from the artifacts, never stored: a "
                "record that says it is stale cannot say why")

    def own_health(self, root: str = ".") -> str:
        """'OK', or the reason this record cannot be believed.

        A PASS with no artifact is not evidence of anything, so it is
        refused here rather than reported as a pass.
        """
        if self.status in ADVANCING and not self.artifacts:
            return "NO_ARTIFACT"
        for a in self.artifacts:
            state = a.check(root)
            if state != "OK":
                return state
        return "OK"


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------
class Ledger:
    def __init__(self, records: Optional[Sequence[Record]] = None,
                 root: str = "."):
        self.records: List[Record] = list(records or [])
        self.root = root

    # -- construction -------------------------------------------------
    @classmethod
    def from_dict(cls, doc: dict, root: str = ".") -> "Ledger":
        if doc.get("schema") != SCHEMA:
            raise LedgerFormatError(
                f"schema is {doc.get('schema')!r}, expected {SCHEMA!r}")
        records = []
        for i, raw in enumerate(doc.get("records", [])):
            try:
                records.append(Record(
                    key=key_from_dict(raw["key"]),
                    stage=raw["stage"],
                    status=raw["status"],
                    artifacts=[Artifact(a["path"], a["sha256"])
                               for a in raw.get("artifacts", [])],
                    note=raw.get("note", ""),
                    observed_utc=raw.get("observed_utc", ""),
                ))
            except KeyError as exc:
                raise LedgerFormatError(
                    f"record {i} is missing {exc}") from exc
        return cls(records, root)

    @classmethod
    def load(cls, path: str, root: Optional[str] = None) -> "Ledger":
        """Read the ledger. A missing file is an empty ledger, not an error.

        An empty ledger reports every stage as NOT_RUN, which is the true
        statement about a checkout that has not qualified anything -- and is
        a different statement from the NOT_BUILT literals it replaces, which
        asserted a build outcome nobody had measured.
        """
        if not os.path.exists(path):
            return cls([], root or os.path.dirname(os.path.abspath(path)) or ".")
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        return cls.from_dict(doc, root or os.path.dirname(os.path.abspath(path)) or ".")

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "stages": list(STAGES),
            "statuses": list(STATUSES),
            "records": [
                {"key": {f: getattr(r.key, f) for f in KEY_FIELDS},
                 "stage": r.stage,
                 "status": r.status,
                 "artifacts": [asdict(a) for a in r.artifacts],
                 "note": r.note,
                 "observed_utc": r.observed_utc}
                for r in self.records
            ],
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self.to_dict(), f, indent=1)

    def add(self, record: Record) -> None:
        self.records.append(record)

    # -- reading ------------------------------------------------------
    def matching(self, key: Key, stage: Optional[str] = None) -> List[Record]:
        """Every record for exactly this key (and stage, if given)."""
        return [r for r in self.records
                if r.key.as_tuple() == key.as_tuple()
                and (stage is None or r.stage == stage)]

    def status(self, key: Key, stage: str) -> str:
        """The status of one stage for one key, as it stands right now.

        `STALE` and `NOT_RUN` are computed here rather than stored, so a
        record cannot claim a status the artifacts do not support.
        """
        if stage not in STAGES:
            raise LedgerFormatError(f"unknown stage {stage!r}")
        found = self.matching(key, stage)
        if not found:
            return "NOT_RUN"
        healthy = [r for r in found if r.own_health(self.root) == "OK"]
        if not healthy:
            # Every record for this stage is unsupported by its artifacts.
            return "STALE"
        # The most recent healthy record wins; ties broken by the last one
        # added, which is the order the file was written in.
        return healthy[-1].status

    def statuses_for(self, key: Key) -> Dict[str, str]:
        """Every stage for one key. Deliberately not an aggregate."""
        return {s: self.status(key, s) for s in STAGES}

    def stale_records(self) -> List[Tuple[Record, str]]:
        """Every record whose artifacts no longer support it."""
        out = []
        for r in self.records:
            health = r.own_health(self.root)
            if health != "OK":
                out.append((r, health))
        return out

    def untraceable(self, key: Key, stage: str) -> List[Record]:
        """Records for `stage` that exist but do not match `key` in full.

        Returned rather than discarded, because "there is a PASS for a
        different object" is the fact a reader most needs to see when a
        decision comes back negative.
        """
        return [r for r in self.records
                if r.stage == stage and r.key.as_tuple() != key.as_tuple()]


# ---------------------------------------------------------------------------
# decisions
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    advance: bool
    reasons: List[str]
    per_stage: Dict[str, str]
    near_misses: List[str] = field(default_factory=list)

    def lines(self) -> List[str]:
        out = [f"{'ADVANCE' if self.advance else 'HOLD'}: "
               f"{'; '.join(self.reasons) if self.reasons else 'all stages pass'}"]
        for stage in STAGES:
            if stage in self.per_stage:
                out.append(f"  {stage:20s} {self.per_stage[stage]}")
        for nm in self.near_misses:
            out.append(f"  (not counted) {nm}")
        return out


def stage_decision(ledger: Ledger, key: Key, required: Sequence[str]) -> Decision:
    """Whether `required` stages all PASS for exactly `key`.

    No aggregation: the caller names the stages it means, and a stage it did
    not name cannot satisfy it. `near_misses` lists records that exist for
    the same stage under a different key, so a refusal can be read.
    """
    per_stage = {}
    reasons = []
    near = []
    for stage in required:
        if stage not in STAGES:
            raise LedgerFormatError(f"unknown stage {stage!r}")
        st = ledger.status(key, stage)
        per_stage[stage] = st
        if st not in ADVANCING:
            reasons.append(f"{stage}={st}")
        for other in ledger.untraceable(key, stage):
            diff = other.key.differences(key)
            near.append(f"{stage}: a {other.status} record exists for a "
                        f"different key (differs in {diff}): "
                        f"{other.key.short()}")
    return Decision(advance=not reasons, reasons=reasons, per_stage=per_stage,
                    near_misses=near)


#: The stages J3's advancement depends on, and only these.
J3_REQUIRED_STAGES: Tuple[str, ...] = (
    "HOST_STATIC",
    "HOST_NUMERIC",
    "ISOLATED_PHYSICAL",
    "AUTHENTIC_DISPATCH",
    "COMPLETE_JOB",
)


def j3_decision(ledger: Ledger, key: Key) -> Decision:
    """Whether J3 may advance, for exactly this key.

    Two refusals on top of the per-stage ones:

      * the key's `source_profile` must be the kernel under qualification.
        A record measured against a different source is not evidence about
        this one, whatever its stages say.
      * a final-head profile is refused outright. The contributor's artifact
        set is a separate chain with a different source object and fixture;
        its PASS is a real PASS about *that* set and must not be read as
        advancing J3. This is a refusal on the profile rather than on the
        stage statuses, so it holds even if someone later records every
        required stage as PASS under that profile.
    """
    if key.is_final_head():
        return Decision(
            advance=False,
            reasons=[f"source_profile {key.source_profile!r} is a final-head "
                     "profile: a PASS there is evidence about that artifact "
                     "set, not about J3"],
            per_stage=ledger.statuses_for(key))
    if key.source_profile != J3_SOURCE_PROFILE:
        return Decision(
            advance=False,
            reasons=[f"source_profile {key.source_profile!r} is not the "
                     f"kernel under qualification ({J3_SOURCE_PROFILE!r})"],
            per_stage=ledger.statuses_for(key))
    return stage_decision(ledger, key, J3_REQUIRED_STAGES)


def report(ledger: Ledger, key: Optional[Key] = None) -> List[str]:
    lines = [f"ledger: {len(ledger.records)} records, "
             f"{len(STAGES)} stages, {len(STATUSES)} statuses"]
    stale = ledger.stale_records()
    lines.append(f"records whose artifacts no longer support them: {len(stale)}")
    for rec, why in stale:
        lines.append(f"  - {rec.stage} {rec.status} -> {why}: "
                     f"{rec.key.short()}")
    if key is not None:
        lines.append(f"key: {key.short()}")
        for stage in STAGES:
            lines.append(f"  {stage:20s} {ledger.status(key, stage)}")
        for line in j3_decision(ledger, key).lines():
            lines.append(f"j3: {line}")
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger",
                    default=os.path.join("audit", "QUALIFICATION_LEDGER.json"))
    ap.add_argument("--key", metavar="JSON",
                    help="a JSON object with all eight key fields")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    ledger = Ledger.load(args.ledger)
    key = key_from_dict(json.loads(args.key)) if args.key else None
    if args.quiet:
        print(f"STATUS OK RECORDS {len(ledger.records)} "
              f"STALE {len(ledger.stale_records())}")
        return 0
    for line in report(ledger, key):
        print(line)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LedgerError as exc:
        print(f"STATUS FAILED {type(exc).__name__}: {exc}")
        raise SystemExit(1)
