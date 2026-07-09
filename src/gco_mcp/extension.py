from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


EXTENSION_ID = "com.alderlinesystems.gco"
META_GCO = f"{EXTENSION_ID}/gco"
META_PARENT_GCO = f"{EXTENSION_ID}/parent_gco"
META_HANDLE = f"{EXTENSION_ID}/handle"


@dataclass(frozen=True)
class GcoExtensionSettings:
    """Settings advertised as the GCO MCP extension capability value."""

    version: str = "1"
    gco_versions: tuple[str, ...] = ("1.0.0",)
    require_gco: bool = True
    max_gco_bytes: int = 65_536
    handle_support: bool = False

    def as_capability(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "gcoVersions": list(self.gco_versions),
            "requireGco": self.require_gco,
            "maxGcoBytes": self.max_gco_bytes,
            "handleSupport": self.handle_support,
        }


def client_extensions_block(settings: GcoExtensionSettings | None = None) -> dict[str, Any]:
    """Return a clientCapabilities.extensions block advertising GCO support."""

    return {EXTENSION_ID: (settings or GcoExtensionSettings()).as_capability()}


def server_extensions_block(settings: GcoExtensionSettings | None = None) -> dict[str, Any]:
    """Return a server/discover capabilities.extensions block advertising GCO support."""

    return {EXTENSION_ID: (settings or GcoExtensionSettings()).as_capability()}


def peer_supports_gco(capabilities: Mapping[str, Any] | None) -> bool:
    """Detect GCO support in a capabilities object or an extensions block."""

    if capabilities is None:
        return False
    extensions = capabilities.get("extensions", capabilities)
    return isinstance(extensions, Mapping) and EXTENSION_ID in extensions
