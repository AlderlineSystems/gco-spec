from __future__ import annotations

from typing import Any

from gco.models import AccessMode, GCO, StatePermission, TaintPolicy
from gco.validator import _taint_rank


class NamespaceAccessDenied(Exception):
    pass


class StateKeyNotFound(NamespaceAccessDenied):
    pass


class TaintedStateRead(Exception):
    pass


class GovernedStateStore:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], bytes] = {}
        self._taints: dict[tuple[str, str], TaintPolicy] = {}

    def write(self, namespace: str, key: str, value: bytes, gco: GCO) -> None:
        permission = self._permission_for(namespace, gco)
        if permission.access_mode not in {AccessMode.WRITE, AccessMode.APPEND}:
            raise NamespaceAccessDenied(f"write denied for namespace {namespace}")
        storage_key = (namespace, key)
        if permission.access_mode is AccessMode.APPEND and storage_key in self._values:
            raise NamespaceAccessDenied(f"append denied for existing key {namespace}/{key}")
        self._values[storage_key] = value
        if storage_key in self._taints:
            self._taints[storage_key] = self._higher_taint(self._taints[storage_key], permission.taint_policy)
        else:
            self._taints[storage_key] = permission.taint_policy

    def read(self, namespace: str, key: str, gco: GCO) -> bytes:
        permission = self._permission_for(namespace, gco)
        if permission.access_mode not in {AccessMode.READ, AccessMode.WRITE, AccessMode.APPEND}:
            raise NamespaceAccessDenied(f"read denied for namespace {namespace}")
        storage_key = (namespace, key)
        if storage_key not in self._values or storage_key not in self._taints:
            raise StateKeyNotFound(f"state key {namespace}/{key} was not found")
        stored_taint = self._taints[storage_key]
        stored_rank = _taint_rank(stored_taint)
        sanitized_rank = _taint_rank(TaintPolicy.SANITIZED)
        # The store enforces quarantine plus unknown-fails-closed only. Reader-vs-data
        # taint alignment beyond quarantine is handled at grant validation today.
        if stored_rank is None or sanitized_rank is None or stored_rank > sanitized_rank:
            raise TaintedStateRead(f"tainted state rejected for {namespace}/{key}")
        return self._values[storage_key]

    def get_taint(self, namespace: str, key: str) -> TaintPolicy:
        storage_key = (namespace, key)
        if storage_key not in self._taints:
            raise StateKeyNotFound(f"state key {namespace}/{key} was not found")
        return self._taints[storage_key]

    def _permission_for(self, namespace: str, gco: GCO) -> StatePermission:
        for permission in gco.state_access_permissions:
            if permission.namespace == namespace:
                return permission
        raise NamespaceAccessDenied(f"namespace {namespace} is not delegated")

    def _higher_taint(self, existing_taint: Any, writer_taint: Any) -> Any:
        existing_rank = _taint_rank(existing_taint)
        writer_rank = _taint_rank(writer_taint)
        if existing_rank is None:
            return existing_taint
        if writer_rank is None:
            return writer_taint
        if existing_rank >= writer_rank:
            return existing_taint
        return writer_taint
