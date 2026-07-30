from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from conftest import make_root_gco
from gco.policy_ledger import (
    GENESIS_PREV_HASH,
    ActivationEventType,
    LedgerAppendError,
    LedgerIntegrityError,
    PolicyActivationRecord,
    PolicyDeploymentLedger,
    compute_entry_hash,
)


FIXED_NOW = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)


def _ledger(**kwargs) -> PolicyDeploymentLedger:
    return PolicyDeploymentLedger(now=lambda: FIXED_NOW, id_factory=lambda: "evt-fixed", **kwargs)


def test_empty_ledger_basics():
    ledger = _ledger()
    assert len(ledger) == 0
    assert ledger.entries() == ()
    assert ledger.head_hash() is None
    assert ledger.active_policies() == {}
    assert ledger.latest_for_policy("policy-alpha") is None
    ledger.verify()
    with pytest.raises(LedgerIntegrityError, match="ledger is empty"):
        ledger.verify(expected_head="abc")


def test_record_activation_chains_hashes():
    ledger = _ledger()
    first = ledger.record_activation(
        policy_id="policy-alpha",
        intervention_version="v1",
        actor="spiffe://example.org/ops",
        reason="initial rollout",
        metadata={"channel": "canary"},
    )
    second = ledger.record_activation(
        policy_id="policy-alpha",
        intervention_version="v2",
        event_type=ActivationEventType.SUPERSEDE,
        event_id="evt-2",
        recorded_at=FIXED_NOW + timedelta(hours=1),
    )

    assert first.sequence == 0
    assert first.prev_entry_hash == GENESIS_PREV_HASH
    assert first.entry_hash == compute_entry_hash(first.body_for_hash())
    assert second.sequence == 1
    assert second.prev_entry_hash == first.entry_hash
    assert second.event_type is ActivationEventType.SUPERSEDE
    assert ledger.head_hash() == second.entry_hash
    ledger.verify()
    ledger.verify(expected_head=second.entry_hash)


def test_record_from_gco_uses_policy_fields():
    gco = make_root_gco()
    ledger = _ledger()
    record = ledger.record_from_gco(gco, deployment_id="dep-1", reason="from gco")

    assert record.policy_id == gco.policy_id
    assert record.intervention_version == gco.intervention_version
    assert record.actor == gco.model_identity
    assert record.deployment_id == "dep-1"
    assert record.event_type is ActivationEventType.ACTIVATE


def test_active_policies_activate_supersede_deactivate():
    ledger = PolicyDeploymentLedger(
        now=lambda: FIXED_NOW,
        id_factory=lambda: "id",
    )
    t0 = FIXED_NOW
    t1 = FIXED_NOW + timedelta(minutes=10)
    t2 = FIXED_NOW + timedelta(minutes=20)
    t3 = FIXED_NOW + timedelta(minutes=30)

    ledger.record_activation(
        policy_id="a", intervention_version="1", event_id="1", recorded_at=t0
    )
    ledger.record_activation(
        policy_id="b", intervention_version="1", event_id="2", recorded_at=t1
    )
    ledger.record_activation(
        policy_id="a",
        intervention_version="2",
        event_type="supersede",
        event_id="3",
        recorded_at=t2,
    )
    ledger.record_activation(
        policy_id="b",
        intervention_version="1",
        event_type=ActivationEventType.DEACTIVATE,
        event_id="4",
        recorded_at=t3,
    )

    mid = ledger.active_policies(at=t1)
    assert set(mid) == {"a", "b"}
    assert mid["a"].intervention_version == "1"

    final = ledger.active_policies()
    assert set(final) == {"a"}
    assert final["a"].intervention_version == "2"
    assert final["a"].event_type is ActivationEventType.SUPERSEDE

    assert ledger.latest_for_policy("b").event_type is ActivationEventType.DEACTIVATE
    assert ledger.latest_for_policy("missing") is None


def test_active_policies_rejects_naive_at():
    ledger = _ledger()
    with pytest.raises(ValueError, match="timezone-aware"):
        ledger.active_policies(at=datetime(2099, 1, 1))


def test_verify_detects_mutated_entry():
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    ledger.record_activation(policy_id="p", intervention_version="2", event_id="2")
    mutated = ledger.entries()[0].model_copy(update={"policy_id": "evil"})
    ledger._entries[0] = mutated
    with pytest.raises(LedgerIntegrityError, match="entry_hash mismatch"):
        ledger.verify()


def test_verify_detects_prev_hash_break():
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    ledger.record_activation(policy_id="p", intervention_version="2", event_id="2")
    broken = ledger.entries()[1].model_copy(update={"prev_entry_hash": GENESIS_PREV_HASH})
    # keep entry_hash so the failure is the prev link (recompute would also fail hash)
    ledger._entries[1] = broken
    with pytest.raises(LedgerIntegrityError, match="prev_entry_hash mismatch"):
        ledger.verify()


def test_verify_detects_sequence_gap():
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    ledger.record_activation(policy_id="p", intervention_version="2", event_id="2")
    bad = ledger.entries()[1].model_copy(update={"sequence": 99})
    ledger._entries[1] = bad
    with pytest.raises(LedgerIntegrityError, match="sequence gap"):
        ledger.verify()


def test_verify_detects_wrong_expected_head():
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    with pytest.raises(LedgerIntegrityError, match="head hash does not match"):
        ledger.verify(expected_head="0" * 64)


def test_append_validation_errors():
    ledger = _ledger()
    with pytest.raises(LedgerAppendError, match="unknown event_type"):
        ledger.record_activation(policy_id="p", intervention_version="1", event_type="nope")
    with pytest.raises(LedgerAppendError, match="policy_id"):
        ledger.record_activation(policy_id="  ", intervention_version="1")
    with pytest.raises(LedgerAppendError, match="intervention_version"):
        ledger.record_activation(policy_id="p", intervention_version="")
    with pytest.raises(LedgerAppendError, match="timezone-aware"):
        ledger.record_activation(
            policy_id="p",
            intervention_version="1",
            recorded_at=datetime(2099, 1, 1),
        )
    with pytest.raises(LedgerAppendError, match="must be UTC"):
        ledger.record_activation(
            policy_id="p",
            intervention_version="1",
            recorded_at=datetime(2099, 1, 1, tzinfo=timezone(timedelta(hours=2))),
        )
    with pytest.raises(LedgerAppendError, match="event_id"):
        ledger.record_activation(policy_id="p", intervention_version="1", event_id="  ")
    with pytest.raises(LedgerAppendError, match="metadata keys and values must be strings"):
        ledger.record_activation(
            policy_id="p",
            intervention_version="1",
            metadata={"n": 1},  # type: ignore[dict-item]
        )
    with pytest.raises(LedgerAppendError, match="metadata keys must be non-empty"):
        ledger.record_activation(
            policy_id="p",
            intervention_version="1",
            metadata={"": "x"},
        )


def test_jsonl_roundtrip_and_append(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    ledger = PolicyDeploymentLedger(
        path=path,
        now=lambda: FIXED_NOW,
        id_factory=lambda: "evt-1",
    )
    first = ledger.record_activation(policy_id="policy-alpha", intervention_version="v1")
    assert path.exists()
    assert path.read_text(encoding="utf-8").count("\n") == 1

    reloaded = PolicyDeploymentLedger.from_jsonl(
        path,
        now=lambda: FIXED_NOW + timedelta(hours=1),
        id_factory=lambda: "evt-2",
    )
    assert len(reloaded) == 1
    assert reloaded.entries()[0].entry_hash == first.entry_hash
    reloaded.verify(expected_head=first.entry_hash)

    second = reloaded.record_activation(
        policy_id="policy-alpha",
        intervention_version="v2",
        event_type=ActivationEventType.SUPERSEDE,
    )
    assert second.prev_entry_hash == first.entry_hash
    assert path.read_text(encoding="utf-8").count("\n") == 2

    again = PolicyDeploymentLedger.from_jsonl(path)
    assert len(again) == 2
    again.verify(expected_head=second.entry_hash)


def test_export_jsonl_and_empty_file(tmp_path: Path):
    empty_path = tmp_path / "empty.jsonl"
    empty_path.write_text("", encoding="utf-8")
    empty = PolicyDeploymentLedger.from_jsonl(empty_path)
    assert len(empty) == 0

    blank = _ledger()
    blank_out = tmp_path / "nested" / "blank-export.jsonl"
    blank.export_jsonl(blank_out)
    assert blank_out.read_text(encoding="utf-8") == ""

    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    out = tmp_path / "export.jsonl"
    ledger.export_jsonl(out)
    loaded = PolicyDeploymentLedger.from_jsonl(out)
    assert loaded.head_hash() == ledger.head_hash()
    assert ledger.to_jsonl_lines()


def test_malformed_jsonl_line_raises(tmp_path: Path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not-json\n", encoding="utf-8")
    with pytest.raises(LedgerIntegrityError, match="malformed ledger line 1"):
        PolicyDeploymentLedger.from_jsonl(path)


def test_load_skips_blank_lines(tmp_path: Path):
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    path = tmp_path / "with-blanks.jsonl"
    path.write_text("\n" + ledger.to_jsonl_lines()[0] + "\n\n", encoding="utf-8")
    loaded = PolicyDeploymentLedger.from_jsonl(path)
    assert len(loaded) == 1


def test_load_can_skip_verify(tmp_path: Path):
    ledger = _ledger()
    ledger.record_activation(policy_id="p", intervention_version="1", event_id="1")
    path = tmp_path / "tampered.jsonl"
    lines = ledger.to_jsonl_lines()
    payload = json.loads(lines[0])
    payload["policy_id"] = "evil"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    loaded = PolicyDeploymentLedger.from_jsonl(path, verify=False)
    assert loaded.entries()[0].policy_id == "evil"
    with pytest.raises(LedgerIntegrityError):
        loaded.verify()


def test_record_model_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        PolicyActivationRecord(
            sequence=0,
            event_id="e",
            recorded_at=datetime(2099, 1, 1),
            event_type=ActivationEventType.ACTIVATE,
            policy_id="p",
            intervention_version="1",
            prev_entry_hash=GENESIS_PREV_HASH,
            entry_hash="a" * 64,
        )


def test_record_model_rejects_non_utc_offset():
    with pytest.raises(ValidationError):
        PolicyActivationRecord(
            sequence=0,
            event_id="e",
            recorded_at=datetime(2099, 1, 1, tzinfo=timezone(timedelta(hours=-5))),
            event_type=ActivationEventType.SUPERSEDE,
            policy_id="p",
            intervention_version="1",
            prev_entry_hash=GENESIS_PREV_HASH,
            entry_hash="a" * 64,
        )


def test_record_model_rejects_empty_hashes():
    with pytest.raises(ValidationError):
        PolicyActivationRecord(
            sequence=0,
            event_id=" ",
            recorded_at=FIXED_NOW,
            event_type=ActivationEventType.ACTIVATE,
            policy_id="p",
            intervention_version="1",
            prev_entry_hash=GENESIS_PREV_HASH,
            entry_hash="a" * 64,
        )


def test_path_property_and_default_factories():
    ledger = PolicyDeploymentLedger()
    assert ledger.path is None
    record = ledger.record_activation(policy_id="p", intervention_version="v")
    assert record.event_id  # uuid default
    assert record.recorded_at.tzinfo is not None
