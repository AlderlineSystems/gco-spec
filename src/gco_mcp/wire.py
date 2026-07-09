from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import ValidationError

from gco.models import GCO

from gco_mcp.errors import GcoMcpError
from gco_mcp.extension import GcoExtensionSettings, META_GCO, META_HANDLE, META_PARENT_GCO


@dataclass(frozen=True)
class WireGco:
    gco: GCO
    parent: GCO | None = None
    handle: str | None = None


class WireError(ValueError):
    def __init__(self, error_code: GcoMcpError, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class GcoWireCodec:
    """Serialize and parse GCO authority objects in MCP request ``_meta``."""

    def __init__(self, settings: GcoExtensionSettings | None = None) -> None:
        self.settings = settings or GcoExtensionSettings()

    def attach(self, meta: Mapping[str, Any] | None, gco: GCO, *, parent: GCO | None = None) -> dict[str, Any]:
        """Return a new ``_meta`` dict with the child GCO and optional parent attached."""

        gco_payload = self._dump_gco(gco)
        self._enforce_size(gco_payload)
        next_meta = dict(meta or {})
        next_meta[META_GCO] = gco_payload
        if parent is not None:
            parent_payload = self._dump_gco(parent)
            self._enforce_size(parent_payload)
            next_meta[META_PARENT_GCO] = parent_payload
        return next_meta

    def extract(self, meta: Mapping[str, Any] | None) -> WireGco:
        """Extract and validate GCO material from MCP request ``_meta``."""

        if meta is None or META_GCO not in meta:
            raise WireError(GcoMcpError.MISSING_GCO, "GCO _meta entry is required")
        gco = self._load_gco(meta[META_GCO])
        parent = self._load_gco(meta[META_PARENT_GCO]) if META_PARENT_GCO in meta else None
        handle = self._load_handle(meta[META_HANDLE]) if META_HANDLE in meta else None
        return WireGco(gco=gco, parent=parent, handle=handle)

    def extension_capability(self) -> dict[str, Any]:
        return self.settings.as_capability()

    def _dump_gco(self, gco: GCO) -> dict[str, Any]:
        return gco.model_dump(mode="json")

    def _load_gco(self, payload: Any) -> GCO:
        self._enforce_size(payload)
        try:
            return GCO.model_validate(payload)
        except (ValidationError, TypeError, ValueError) as exc:
            raise WireError(GcoMcpError.MALFORMED_GCO, "GCO _meta entry is malformed") from exc

    def _load_handle(self, payload: Any) -> str:
        if not isinstance(payload, str) or not payload:
            raise WireError(GcoMcpError.MALFORMED_GCO, "GCO handle _meta entry is malformed")
        return payload

    def _enforce_size(self, payload: Any) -> None:
        try:
            size = len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise WireError(GcoMcpError.MALFORMED_GCO, "GCO _meta entry is not JSON serializable") from exc
        if size > self.settings.max_gco_bytes:
            raise WireError(GcoMcpError.OVERSIZE_GCO, "GCO _meta entry exceeds maxGcoBytes")
