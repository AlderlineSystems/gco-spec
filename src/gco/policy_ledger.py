"""Tamper-evident append-only policy / deployment activation ledger.

Records which ``policy_id`` / ``intervention_version`` values were activated
(and later deactivated or superseded), for accountability and forensics.

Integrity model (v1)
--------------------
Each entry carries a SHA-256 hash over a canonical JSON encoding of its body
fields plus the previous entry's hash (genesis uses ``GENESIS_PREV_HASH``).
``verify()`` walks the chain and rejects reordered, mutated, truncated (when an
expected head is supplied), or re-hashed-in-place breaks of the stored sequence.

This is **tamper-evident**, not multi-party consensus:

* An attacker who can rewrite the entire store *and* recompute every hash from
  genesis can forge a plausible alternate history **unless** an externally
  sealed head hash (or earlier checkpoint) is compared via
  ``verify(expected_head=...)``.
* Callers that need stronger guarantees should publish ``head_hash()`` to an
  external log, transparency service, or signed checkpoint.

v1 limits (honest)
------------------
* Single-writer / single-process; not a multi-tenant control plane.
* Does not replace ``TrustBundle`` or GCO attestation crypto.
* Optional JSONL file backend is durable append, not crash-safe multi-writer.
* Metadata values are constrained to strings for stable canonicalization.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from gco.models import GCO, StrictBaseModel

GENESIS_PREV_HASH = "0" * 64


class ActivationEventType(str, Enum):
    """Lifecycle events recorded for a deployed policy version."""

    ACTIVATE = "activate"
    DEACTIVATE = "deactivate"
    SUPERSEDE = "supersede"


class LedgerError(Exception):
    """Base error for policy deployment ledger failures."""


class LedgerIntegrityError(LedgerError):
    """Raised when the hash chain or sequence invariants do not hold."""


class LedgerAppendError(LedgerError):
    """Raised when an append is rejected (validation or storage failure)."""


class PolicyActivationRecord(StrictBaseModel):
    """One append-only activation (or deactivation / supersession) event."""

    sequence: int = Field(ge=0)
    event_id: str
    recorded_at: datetime
    event_type: ActivationEventType
    policy_id: str = Field(min_length=1)
    intervention_version: str = Field(min_length=1)
    deployment_id: str | None = None
    actor: str | None = None
    reason: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    prev_entry_hash: str
    entry_hash: str

    @field_validator("recorded_at")
    @classmethod
    def recorded_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware UTC")
        if value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("recorded_at must be UTC")
        return value

    @field_validator("event_id", "prev_entry_hash", "entry_hash")
    @classmethod
    def non_empty_ids(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must be a non-empty string")
        return value

    def body_for_hash(self) -> dict[str, Any]:
        """Canonical body fields that participate in ``entry_hash`` (excludes hash)."""
        return {
            "actor": self.actor,
            "deployment_id": self.deployment_id,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "intervention_version": self.intervention_version,
            "metadata": self.metadata,
            "policy_id": self.policy_id,
            "prev_entry_hash": self.prev_entry_hash,
            "reason": self.reason,
            "recorded_at": _isoformat_utc(self.recorded_at),
            "sequence": self.sequence,
        }


def _isoformat_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def compute_entry_hash(body: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of the canonical JSON body (including prev_entry_hash)."""
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_metadata(metadata: Mapping[str, str] | None) -> dict[str, str]:
    if metadata is None:
        return {}
    normalized: dict[str, str] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise LedgerAppendError("metadata keys and values must be strings")
        if not key:
            raise LedgerAppendError("metadata keys must be non-empty")
        normalized[key] = value
    return normalized


def _active_snapshot(records: Iterable[PolicyActivationRecord]) -> dict[str, PolicyActivationRecord]:
    """Apply activation lifecycle events in order; return policy_id -> latest active record."""
    active: dict[str, PolicyActivationRecord] = {}
    for record in records:
        if record.event_type is ActivationEventType.DEACTIVATE:
            active.pop(record.policy_id, None)
        else:
            # activate and supersede both place/replace the active version
            active[record.policy_id] = record
    return active


class PolicyDeploymentLedger:
    """Append-only, hash-chained ledger of policy deployment activations.

    Wire points
    -----------
    * Call :meth:`record_activation` (or :meth:`record_from_gco`) when a host
      activates, deactivates, or supersedes a policy that will appear on GCOs.
    * Call :meth:`verify` (optionally with a previously sealed ``expected_head``)
      before trusting historical queries for forensics.
    * Persist via ``path=`` (JSONL) or keep in memory for tests / single process.
    """

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        now: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        verify_on_load: bool = True,
    ) -> None:
        self._path = Path(path) if path is not None else None
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self._entries: list[PolicyActivationRecord] = []
        self._usable = True
        if self._path is not None and self._path.exists():
            self._load_jsonl(self._path)
            if verify_on_load:
                self.verify()

    @property
    def path(self) -> Path | None:
        return self._path

    def __len__(self) -> int:
        self._ensure_usable()
        return len(self._entries)

    def entries(self) -> tuple[PolicyActivationRecord, ...]:
        self._ensure_usable()
        return tuple(self._entries)

    def head_hash(self) -> str | None:
        """Hash of the latest entry, or ``None`` when the ledger is empty."""
        self._ensure_usable()
        if not self._entries:
            return None
        return self._entries[-1].entry_hash

    def record_activation(
        self,
        *,
        policy_id: str,
        intervention_version: str,
        event_type: ActivationEventType | str = ActivationEventType.ACTIVATE,
        deployment_id: str | None = None,
        actor: str | None = None,
        reason: str | None = None,
        metadata: Mapping[str, str] | None = None,
        recorded_at: datetime | None = None,
        event_id: str | None = None,
    ) -> PolicyActivationRecord:
        """Append one activation lifecycle event and return the sealed record."""
        self._ensure_usable()
        if not isinstance(event_type, ActivationEventType):
            try:
                event_type = ActivationEventType(event_type)
            except ValueError as exc:
                raise LedgerAppendError(f"unknown event_type: {event_type!r}") from exc

        if not policy_id or not str(policy_id).strip():
            raise LedgerAppendError("policy_id must be a non-empty string")
        if not intervention_version or not str(intervention_version).strip():
            raise LedgerAppendError("intervention_version must be a non-empty string")

        when = recorded_at if recorded_at is not None else self._now()
        if when.tzinfo is None or when.utcoffset() is None:
            raise LedgerAppendError("recorded_at must be timezone-aware UTC")
        if when.utcoffset() != timezone.utc.utcoffset(when):
            raise LedgerAppendError("recorded_at must be UTC")

        sequence = len(self._entries)
        prev = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        eid = event_id if event_id is not None else self._id_factory()
        if not eid or not str(eid).strip():
            raise LedgerAppendError("event_id must be a non-empty string")

        meta = _normalize_metadata(metadata)
        body = {
            "actor": actor,
            "deployment_id": deployment_id,
            "event_id": eid,
            "event_type": event_type.value,
            "intervention_version": intervention_version,
            "metadata": meta,
            "policy_id": policy_id,
            "prev_entry_hash": prev,
            "reason": reason,
            "recorded_at": _isoformat_utc(when),
            "sequence": sequence,
        }
        entry_hash = compute_entry_hash(body)
        record = PolicyActivationRecord(
            sequence=sequence,
            event_id=eid,
            recorded_at=when.astimezone(timezone.utc),
            event_type=event_type,
            policy_id=policy_id,
            intervention_version=intervention_version,
            deployment_id=deployment_id,
            actor=actor,
            reason=reason,
            metadata=meta,
            prev_entry_hash=prev,
            entry_hash=entry_hash,
        )
        self._append(record)
        return record

    def record_from_gco(
        self,
        gco: GCO,
        *,
        event_type: ActivationEventType | str = ActivationEventType.ACTIVATE,
        deployment_id: str | None = None,
        actor: str | None = None,
        reason: str | None = None,
        metadata: Mapping[str, str] | None = None,
        recorded_at: datetime | None = None,
        event_id: str | None = None,
    ) -> PolicyActivationRecord:
        """Record an activation event using ``policy_id`` / ``intervention_version`` from a GCO."""
        return self.record_activation(
            policy_id=gco.policy_id,
            intervention_version=gco.intervention_version,
            event_type=event_type,
            deployment_id=deployment_id,
            actor=actor if actor is not None else gco.model_identity,
            reason=reason,
            metadata=metadata,
            recorded_at=recorded_at,
            event_id=event_id,
        )

    def verify(self, *, expected_head: str | None = None) -> None:
        """Validate sequence numbers and the hash chain; optionally pin the head hash."""
        self._ensure_usable()
        prev = GENESIS_PREV_HASH
        for index, record in enumerate(self._entries):
            if record.sequence != index:
                raise LedgerIntegrityError(
                    f"sequence gap or reorder at index {index}: found sequence={record.sequence}"
                )
            if record.prev_entry_hash != prev:
                raise LedgerIntegrityError(
                    f"prev_entry_hash mismatch at sequence {record.sequence}"
                )
            expected = compute_entry_hash(record.body_for_hash())
            if record.entry_hash != expected:
                raise LedgerIntegrityError(
                    f"entry_hash mismatch at sequence {record.sequence}"
                )
            prev = record.entry_hash
        if expected_head is not None:
            head = self.head_hash()
            if head is None:
                raise LedgerIntegrityError("expected_head provided but ledger is empty")
            if head != expected_head:
                raise LedgerIntegrityError("head hash does not match expected_head")

    def active_policies(
        self,
        *,
        at: datetime | None = None,
    ) -> dict[str, PolicyActivationRecord]:
        """Return the active policy_id → record map after replaying events.

        When ``at`` is set, only events with ``recorded_at <= at`` are applied.
        """
        self._ensure_usable()
        if at is not None:
            if at.tzinfo is None or at.utcoffset() is None:
                raise ValueError("at must be timezone-aware UTC")
            at_utc = at.astimezone(timezone.utc)
            filtered = sorted(
                (r for r in self._entries if r.recorded_at <= at_utc),
                key=lambda r: (r.recorded_at, r.sequence, r.event_id),
            )
            return _active_snapshot(filtered)
        return _active_snapshot(self._entries)

    def latest_for_policy(self, policy_id: str) -> PolicyActivationRecord | None:
        """Most recent event for ``policy_id``, or ``None`` if never recorded."""
        self._ensure_usable()
        for record in reversed(self._entries):
            if record.policy_id == policy_id:
                return record
        return None

    def to_jsonl_lines(self) -> list[str]:
        self._ensure_usable()
        return [
            json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
            for record in self._entries
        ]

    def export_jsonl(self, path: str | Path) -> None:
        """Write the full chain to ``path`` (overwrite). Prefer the append path for live use."""
        self._ensure_usable()
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = "\n".join(self.to_jsonl_lines())
        if payload:
            payload += "\n"
        target.write_text(payload, encoding="utf-8")

    @classmethod
    def from_jsonl(
        cls,
        path: str | Path,
        *,
        now: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        verify: bool = True,
    ) -> PolicyDeploymentLedger:
        """Load a JSONL ledger file into a new ledger bound to that path for further appends."""
        return cls(path=path, now=now, id_factory=id_factory, verify_on_load=verify)

    def _append(self, record: PolicyActivationRecord) -> None:
        self._ensure_usable()
        if self._path is not None:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(
                    record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                )
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                self._usable = False
                raise LedgerAppendError(f"failed to append ledger entry: {exc}") from exc
        self._entries.append(record)

    def _ensure_usable(self) -> None:
        if not self._usable:
            raise LedgerAppendError("ledger is unusable after a previous append storage failure")

    def _load_jsonl(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                record = PolicyActivationRecord.model_validate(payload)
            except Exception as exc:  # noqa: BLE001
                raise LedgerIntegrityError(f"malformed ledger line {line_no}: {exc}") from exc
            self._entries.append(record)
