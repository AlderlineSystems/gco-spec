# MCP Extension: com.alderlinesystems.gco

This document captures the P0 wire profile for carrying Alderline GCO authority through MCP `tools/call`.

The adapter is intentionally SDK-agnostic for P0: it accepts and returns plain `_meta` dictionaries and composes `GovernanceRuntime` for all verification, authorization, and derivation. It does not add GCO fields to tool `inputSchema`.

## Capability Settings

Extension id: `com.alderlinesystems.gco`

Capability value:

```json
{
  "version": "1",
  "gcoVersions": ["1.0.0"],
  "requireGco": true,
  "maxGcoBytes": 65536,
  "handleSupport": false
}
```

Servers advertise this under `capabilities.extensions`. Clients advertise it per request under `_meta["io.modelcontextprotocol/clientCapabilities"].extensions`.

## Wire Keys

All GCO material travels in request `_meta` under reverse-DNS keys:

| Key | Value | P0 behavior |
| --- | --- | --- |
| `com.alderlinesystems.gco/gco` | Full GCO JSON object including embedded `attestation` | Required when governed mode is in force |
| `com.alderlinesystems.gco/parent_gco` | Parent GCO JSON object | Optional; used when the receiver should run `authorize_subcall(parent, child)` |
| `com.alderlinesystems.gco/handle` | Opaque handle | Reserved for later handle-store work; P0 parses but does not resolve handles |

`maxGcoBytes` defaults to 65536 and is enforced on serialized GCO JSON for both attach and extract.

## Enforcement Boundaries

E1 client pre-send:

1. `GovernanceRuntime.authorize_tool_call(parent, tool_uri, requested_scope)`
2. `GovernanceRuntime.derive_for_subcall(parent, delegation)`
3. Attach the derived child GCO to `_meta`.

E2 server pre-execute:

1. Require the client capability by default.
2. Extract the child GCO from `_meta`.
3. If `parent_gco` is present, call `GovernanceRuntime.authorize_subcall(parent, child)`.
4. Call `GovernanceRuntime.authorize_tool_call(child, tool_uri, requested_scope)`.

E3 server fan-out:

1. Authorize the current GCO for the outbound tool.
2. Derive a tightened child GCO.
3. Attach that child to the outbound `_meta`, optionally with `parent_gco`.

Both governed boundaries fail closed. Cryptographic verification and tightening are never reimplemented in `gco_mcp`; they always come from `GovernanceRuntime`.

## Error Mapping

| Condition | MCP shape |
| --- | --- |
| Missing GCO extension capability when required | JSON-RPC error code `-32021` (`MissingRequiredClientCapability`) with `data.requiredCapabilities.extensions["com.alderlinesystems.gco"]` |
| Missing, malformed, or oversize GCO `_meta` | JSON-RPC error code `-32602` (`Invalid params`) with stable `data.error_code` |
| Attestation failure, expiry, tool denial, or derivation denial | Tool-level error result with `isError: true` and `structuredContent.error_code` derived from the runtime `Decision` |

Stable adapter error codes:

| Code | Meaning |
| --- | --- |
| `gco_missing_capability` | Required client extension capability was absent |
| `gco_missing` | Required GCO `_meta` key was absent |
| `gco_oversize` | Serialized GCO JSON exceeded `maxGcoBytes` |
| `gco_malformed` | GCO, parent GCO, or handle was malformed |

Runtime denial codes such as `tool_authority_expanded`, `expired`, `gco_digest_mismatch`, and `malformed_attestation` are preserved from `GovernanceRuntime`.
