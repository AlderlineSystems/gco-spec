from __future__ import annotations

import pytest

from gco.models import AccessMode, StatePermission, TaintPolicy
from gco.state_store import GovernedStateStore, NamespaceAccessDenied, StateKeyNotFound, TaintedStateRead
from gco.validator import _taint_rank
from conftest import make_root_gco


def _gco_with_permissions(*permissions: StatePermission):
    return make_root_gco(state_access_permissions=list(permissions))


def test_write_read_and_get_taint():
    store = GovernedStateStore()
    gco = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN)
    )

    store.write("memory", "answer", b"42", gco)

    assert store.read("memory", "answer", gco) == b"42"
    assert store.get_taint("memory", "answer", gco) is TaintPolicy.CLEAN


def test_write_rejects_missing_namespace(valid_root_gco):
    with pytest.raises(NamespaceAccessDenied, match="namespace missing is not delegated"):
        GovernedStateStore().write("missing", "key", b"value", valid_root_gco)


def test_write_rejects_none_access():
    gco = _gco_with_permissions(StatePermission(namespace="blocked", access_mode=AccessMode.NONE))

    with pytest.raises(NamespaceAccessDenied, match="write denied for namespace blocked"):
        GovernedStateStore().write("blocked", "key", b"value", gco)


def test_append_allows_new_key_and_rejects_existing_key():
    store = GovernedStateStore()
    gco = _gco_with_permissions(StatePermission(namespace="log", access_mode=AccessMode.APPEND))

    store.write("log", "entry", b"first", gco)
    with pytest.raises(NamespaceAccessDenied, match="append denied for existing key log/entry"):
        store.write("log", "entry", b"second", gco)
    with pytest.raises(NamespaceAccessDenied, match="read denied for namespace log"):
        store.read("log", "entry", gco)
    with pytest.raises(NamespaceAccessDenied, match="read denied for namespace log"):
        store.get_taint("log", "entry", gco)


def test_read_rejects_none_access():
    store = GovernedStateStore()
    writer = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.WRITE))
    reader = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.NONE))
    store.write("memory", "answer", b"42", writer)

    with pytest.raises(NamespaceAccessDenied):
        store.read("memory", "answer", reader)


def test_read_rejects_tainted_state():
    store = GovernedStateStore()
    gco = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.TAINTED)
    )
    store.write("memory", "answer", b"42", gco)

    with pytest.raises(TaintedStateRead):
        store.read("memory", "answer", gco)


def test_read_rejects_granted_but_unwritten_key_with_controlled_error():
    store = GovernedStateStore()
    gco = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.READ))

    with pytest.raises(StateKeyNotFound, match="state key memory/missing was not found") as exc_info:
        store.read("memory", "missing", gco)

    assert isinstance(exc_info.value, NamespaceAccessDenied)


def test_read_rejects_value_without_taint_with_controlled_error():
    store = GovernedStateStore()
    gco = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.READ))
    store._values[("memory", "answer")] = b"42"

    with pytest.raises(StateKeyNotFound, match="state key memory/answer was not found"):
        store.read("memory", "answer", gco)


def test_get_taint_rejects_missing_key_with_controlled_error():
    store = GovernedStateStore()
    gco = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.READ))

    with pytest.raises(StateKeyNotFound, match="state key memory/missing was not found") as exc_info:
        store.get_taint("memory", "missing", gco)

    assert isinstance(exc_info.value, NamespaceAccessDenied)


def test_get_taint_rejects_ungranted_namespace():
    store = GovernedStateStore()
    writer = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.WRITE))
    store.write("memory", "answer", b"42", writer)
    outsider = _gco_with_permissions(StatePermission(namespace="other", access_mode=AccessMode.READ))

    with pytest.raises(NamespaceAccessDenied, match="namespace memory is not delegated"):
        store.get_taint("memory", "answer", outsider)


def test_get_taint_rejects_none_access():
    store = GovernedStateStore()
    writer = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.WRITE))
    store.write("memory", "answer", b"42", writer)
    blocked = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.NONE))

    with pytest.raises(NamespaceAccessDenied):
        store.get_taint("memory", "answer", blocked)


@pytest.mark.parametrize("access_mode", [AccessMode.READ, AccessMode.WRITE])
def test_get_taint_allows_readable_access_modes(access_mode: AccessMode):
    store = GovernedStateStore()
    writer = _gco_with_permissions(StatePermission(namespace="memory", access_mode=AccessMode.WRITE))
    reader = _gco_with_permissions(StatePermission(namespace="memory", access_mode=access_mode))
    store.write("memory", "answer", b"42", writer)

    assert store.get_taint("memory", "answer", reader) is TaintPolicy.CLEAN


def test_taint_laundering_overwrite_keeps_higher_stored_taint():
    store = GovernedStateStore()
    tainted_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.TAINTED)
    )
    clean_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN)
    )

    store.write("memory", "answer", b"secret", tainted_writer)
    store.write("memory", "answer", b"replacement", clean_writer)

    with pytest.raises(TaintedStateRead, match="tainted state rejected for memory/answer"):
        store.read("memory", "answer", clean_writer)
    assert _taint_rank(store.get_taint("memory", "answer", tainted_writer)) >= _taint_rank(TaintPolicy.TAINTED)


def test_higher_taint_allows_sanitized_over_clean_and_preserves_unknown_existing_taint():
    store = GovernedStateStore()
    clean_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN)
    )
    sanitized_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
    )
    sanitized_reader = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.SANITIZED)
    )

    store.write("memory", "answer", b"clean", clean_writer)
    store.write("memory", "answer", b"sanitized", sanitized_writer)
    # A CLEAN-policy writer is not permitted to read back SANITIZED data (taint alignment).
    with pytest.raises(TaintedStateRead):
        store.read("memory", "answer", clean_writer)
    # A SANITIZED-policy reader may read it.
    assert store.read("memory", "answer", sanitized_reader) == b"sanitized"
    assert store.get_taint("memory", "answer", clean_writer) is TaintPolicy.SANITIZED

    store._taints[("memory", "answer")] = "superbad"
    store.write("memory", "answer", b"clean-again", clean_writer)
    assert store.get_taint("memory", "answer", clean_writer) == "superbad"


def test_unknown_writer_taint_over_existing_clean_key_fails_closed():
    store = GovernedStateStore()
    clean_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.CLEAN)
    )
    bad_permission = StatePermission.model_construct(
        namespace="memory", access_mode=AccessMode.WRITE, taint_policy="superbad"
    )
    unknown_writer = _gco_with_permissions(bad_permission)

    store.write("memory", "answer", b"clean", clean_writer)
    store.write("memory", "answer", b"unknown", unknown_writer)

    assert store.get_taint("memory", "answer", clean_writer) == "superbad"
    with pytest.raises(TaintedStateRead, match="tainted state rejected for memory/answer"):
        store.read("memory", "answer", clean_writer)


def test_unknown_taint_policy_at_read_gate_is_blocked():
    store = GovernedStateStore()
    bad_permission = StatePermission.model_construct(
        namespace="memory", access_mode=AccessMode.WRITE, taint_policy="superbad"
    )
    gco = _gco_with_permissions(bad_permission)

    store.write("memory", "answer", b"42", gco)

    with pytest.raises(TaintedStateRead, match="tainted state rejected for memory/answer"):
        store.read("memory", "answer", gco)


def test_read_rejects_clean_reader_for_sanitized_data():
    store = GovernedStateStore()
    sanitized_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
    )
    clean_reader = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.CLEAN)
    )
    store.write("memory", "answer", b"42", sanitized_writer)

    with pytest.raises(TaintedStateRead, match="tainted state rejected for memory/answer"):
        store.read("memory", "answer", clean_reader)


def test_read_allows_sanitized_reader_for_sanitized_data():
    store = GovernedStateStore()
    sanitized_writer = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.SANITIZED)
    )
    sanitized_reader = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.READ, taint_policy=TaintPolicy.SANITIZED)
    )
    store.write("memory", "answer", b"42", sanitized_writer)

    assert store.read("memory", "answer", sanitized_reader) == b"42"


def test_read_rejects_isolated_state():
    store = GovernedStateStore()
    gco = _gco_with_permissions(
        StatePermission(namespace="memory", access_mode=AccessMode.WRITE, taint_policy=TaintPolicy.ISOLATED)
    )
    store.write("memory", "answer", b"42", gco)

    with pytest.raises(TaintedStateRead, match="tainted state rejected for memory/answer"):
        store.read("memory", "answer", gco)
