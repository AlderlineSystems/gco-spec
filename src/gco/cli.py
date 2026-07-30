from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, NoReturn, TextIO

import jwt
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from gco.attestation import AttestationError, AttestationVerifier, VerificationResult
from gco.derivation import DelegationRequest, GCODerivationRuntime
from gco.models import AttestationFormat, AttestationModel, GCO
from gco.policy_ledger import (
    ActivationEventType,
    LedgerAppendError,
    LedgerError,
    LedgerIntegrityError,
    PolicyDeploymentLedger,
)
from gco.runtime import GovernanceRuntime
from gco.trust import TrustBundle, TrustBundleError
from gco.validator import DerivationError, GCOValidator, canonical_gco_hash


SUCCESS = 0
FAILURE = 1
USAGE = 2


@dataclass(frozen=True)
class CLIError(Exception):
    code: str
    message: str
    exit_status: int = FAILURE


class GCOArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CLIError("USAGE_ERROR", message, USAGE)


class PemSigningAuthority:
    def __init__(self, key: Any, *, kid: str = "gco-cli") -> None:
        self._key = key
        self._kid = kid

    def issue(self, identity: str, gco_data: dict[str, Any]) -> AttestationModel:
        unsigned = GCO.model_validate({**gco_data, "attestation": None})
        subject = unsigned.model_copy(update={"model_identity": identity})
        payload = {"sub": identity, "gco_hash": canonical_gco_hash(subject), "exp": int(subject.expires_at.timestamp())}
        token = jwt.encode(payload, self._key, algorithm="RS256", headers={"kid": self._kid})
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=token, issuer=identity)


class PreviewSigningAuthority:
    def issue(self, identity: str, gco_data: dict[str, Any]) -> AttestationModel:
        return AttestationModel(format=AttestationFormat.JWT_SVID, value=f"preview-unsigned:{identity}")


def main(argv: list[str] | None = None) -> int:
    stdout = sys.stdout
    stderr = sys.stderr
    raw_argv = sys.argv[1:] if argv is None else argv
    as_json = "--json" in raw_argv
    try:
        args = _build_parser().parse_args(raw_argv)
        as_json = bool(args.json)
        return args.func(args, stdout, stderr)
    except CLIError as exc:
        _emit_failure(exc.code, exc.message, as_json, stdout, stderr)
        return exc.exit_status
    except Exception as exc:  # noqa: BLE001
        _emit_failure("GCO_CLI_ERROR", str(exc), as_json, stdout, stderr)
        return FAILURE


def _build_parser() -> argparse.ArgumentParser:
    parser = GCOArgumentParser(prog="gco", description="Debug GCO trust bundles and delegation chains.")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    subcommands = parser.add_subparsers(dest="command", required=True, parser_class=GCOArgumentParser)

    validate = subcommands.add_parser("validate", help="validate a child GCO against a parent GCO")
    validate.add_argument("child")
    validate.add_argument("--parent", required=True)
    validate.set_defaults(func=_cmd_validate)

    verify = subcommands.add_parser("verify", help="verify a GCO attestation against a trust bundle")
    verify.add_argument("gco")
    verify.add_argument("--trust-bundle", required=True)
    verify.set_defaults(func=_cmd_verify)

    inspect = subcommands.add_parser("inspect", help="print a human-readable GCO authority dump")
    inspect.add_argument("gco")
    inspect.set_defaults(func=_cmd_inspect)

    derive = subcommands.add_parser("derive", help="derive a tightened child GCO from a delegation request")
    derive.add_argument("parent")
    derive.add_argument("--request", required=True)
    derive.add_argument("--trust-bundle", required=True)
    derive.add_argument("--sign-key")
    derive.add_argument("--kid", default="gco-cli")
    derive.set_defaults(func=_cmd_derive)

    schema = subcommands.add_parser("schema", help="print the bundled JSON schema path and content")
    schema.set_defaults(func=_cmd_schema)

    ledger_verify = subcommands.add_parser(
        "ledger-verify",
        help="verify the hash chain of a policy deployment ledger (JSONL)",
    )
    ledger_verify.add_argument("ledger", help="path to JSONL policy deployment ledger")
    ledger_verify.add_argument(
        "--expected-head",
        default=None,
        help="optional externally sealed head hash that must match",
    )
    ledger_verify.set_defaults(func=_cmd_ledger_verify)

    ledger_show = subcommands.add_parser(
        "ledger-show",
        help="list entries and active policies from a policy deployment ledger",
    )
    ledger_show.add_argument("ledger", help="path to JSONL policy deployment ledger")
    ledger_show.set_defaults(func=_cmd_ledger_show)

    ledger_record = subcommands.add_parser(
        "ledger-record",
        help="append a policy activation event to a JSONL deployment ledger",
    )
    ledger_record.add_argument("ledger", help="path to JSONL policy deployment ledger")
    ledger_record.add_argument("--policy-id", required=True)
    ledger_record.add_argument("--intervention-version", required=True)
    ledger_record.add_argument(
        "--event-type",
        default=ActivationEventType.ACTIVATE.value,
        choices=[item.value for item in ActivationEventType],
    )
    ledger_record.add_argument("--deployment-id", default=None)
    ledger_record.add_argument("--actor", default=None)
    ledger_record.add_argument("--reason", default=None)
    ledger_record.set_defaults(func=_cmd_ledger_record)
    return parser


def _cmd_validate(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    parent = _load_json(args.parent)
    child = _load_json(args.child)
    result = GCOValidator().validate_result(parent, child)
    if result.valid:
        _emit_success({"decision": "allow"}, args.json, stdout, human="allow")
        return SUCCESS
    code = _code(result.error_code)
    message = result.message or code
    _emit_failure(code, message, args.json, stdout, stderr, prefix="deny")
    return FAILURE


def _cmd_verify(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    gco = _load_gco(args.gco)
    bundle = _load_bundle(args.trust_bundle)
    result = AttestationVerifier(bundle).verify(gco.attestation, gco)
    checks = _verification_checks(result)
    payload = {"verified": result.verified, "checks": checks}
    if result.verified:
        _emit_success(payload, args.json, stdout, human=_format_verify(payload))
        return SUCCESS
    code = _code(result.error_code)
    payload.update({"error_code": code, "message": result.message})
    _emit_failure(code, result.message or code, args.json, stdout, stderr, payload=payload, prefix="deny")
    return FAILURE


def _cmd_inspect(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    gco = _load_gco(args.gco)
    payload = _inspection_payload(gco)
    _emit_success(payload, args.json, stdout, human=_format_inspection(payload))
    return SUCCESS


def _cmd_derive(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    parent = _load_gco(args.parent)
    request = _load_delegation_request(args.request)
    bundle = _load_bundle(args.trust_bundle)
    authority = _load_signing_authority(args.sign_key, args.kid) if args.sign_key else PreviewSigningAuthority()
    runtime = GovernanceRuntime(bundle, attestation_authority=authority)
    if args.sign_key:
        decision = runtime.derive_for_subcall(parent, request)
        if not decision.allowed or decision.child is None:
            code = _code(decision.error_code)
            _emit_failure(code, decision.reason or code, args.json, stdout, stderr, prefix="deny")
            return FAILURE
        payload = {"preview_only": False, "child": decision.child.model_dump(mode="json")}
    else:
        parent_verified = AttestationVerifier(bundle).verify(parent.attestation, parent)
        if not parent_verified.verified:
            code = _code(parent_verified.error_code)
            _emit_failure(code, parent_verified.message or code, args.json, stdout, stderr, prefix="deny")
            return FAILURE
        try:
            child = GCODerivationRuntime(authority).derive(parent, request)
        except Exception as exc:  # noqa: BLE001
            code = _exception_code(exc)
            _emit_failure(code, str(exc), args.json, stdout, stderr, prefix="deny")
            return FAILURE
        payload = {"preview_only": True, "warning": "unsigned derivation is preview-only", "child": child.model_dump(mode="json")}
    human = json.dumps(payload["child"], indent=2, sort_keys=True)
    if payload["preview_only"]:
        human = f"warning: {payload['warning']}\n{human}"
    _emit_success(payload, args.json, stdout, human=human)
    return SUCCESS


def _cmd_schema(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    path = _schema_path()
    schema = _load_json(path)
    payload = {"path": str(path), "schema": schema}
    _emit_success(payload, args.json, stdout, human=f"Schema path: {path}\n{json.dumps(schema, indent=2, sort_keys=True)}")
    return SUCCESS


def _cmd_ledger_verify(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    ledger = _load_policy_ledger(args.ledger)
    try:
        ledger.verify(expected_head=args.expected_head)
    except LedgerIntegrityError as exc:
        raise CLIError("LEDGER_INTEGRITY_ERROR", str(exc)) from exc
    payload = {
        "entries": len(ledger),
        "head_hash": ledger.head_hash(),
        "verified": True,
    }
    human = f"allow: ledger verified\nentries: {payload['entries']}\nhead_hash: {payload['head_hash']}"
    _emit_success(payload, args.json, stdout, human=human)
    return SUCCESS


def _cmd_ledger_show(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    ledger = _load_policy_ledger(args.ledger)
    try:
        ledger.verify()
    except LedgerIntegrityError as exc:
        raise CLIError("LEDGER_INTEGRITY_ERROR", str(exc)) from exc
    entries = [record.model_dump(mode="json") for record in ledger.entries()]
    active = {
        policy_id: record.model_dump(mode="json")
        for policy_id, record in ledger.active_policies().items()
    }
    payload = {
        "active_policies": active,
        "entries": entries,
        "head_hash": ledger.head_hash(),
    }
    if args.json:
        _emit_success(payload, True, stdout, human="")
        return SUCCESS
    lines = [
        f"entries: {len(entries)}",
        f"head_hash: {payload['head_hash']}",
        "active policies:",
    ]
    if not active:
        lines.append("  (none)")
    else:
        for policy_id, record in sorted(active.items()):
            lines.append(
                f"  - {policy_id} intervention={record['intervention_version']} "
                f"event={record['event_type']} seq={record['sequence']}"
            )
    lines.append("history:")
    if not entries:
        lines.append("  (empty)")
    else:
        for record in entries:
            lines.append(
                f"  - [{record['sequence']}] {record['event_type']} "
                f"{record['policy_id']}@{record['intervention_version']} "
                f"hash={record['entry_hash'][:12]}…"
            )
    _emit_success(payload, False, stdout, human="\n".join(lines))
    return SUCCESS


def _cmd_ledger_record(args: argparse.Namespace, stdout: TextIO, stderr: TextIO) -> int:
    path = Path(args.ledger)
    try:
        ledger = PolicyDeploymentLedger(path=path)
        record = ledger.record_activation(
            policy_id=args.policy_id,
            intervention_version=args.intervention_version,
            event_type=args.event_type,
            deployment_id=args.deployment_id,
            actor=args.actor,
            reason=args.reason,
        )
    except (LedgerAppendError, LedgerIntegrityError, LedgerError) as exc:
        code = (
            "LEDGER_INTEGRITY_ERROR"
            if isinstance(exc, LedgerIntegrityError)
            else "LEDGER_APPEND_ERROR"
        )
        raise CLIError(code, str(exc)) from exc
    payload = {"head_hash": ledger.head_hash(), "record": record.model_dump(mode="json")}
    human = (
        f"recorded: {record.event_type.value} {record.policy_id}@"
        f"{record.intervention_version} seq={record.sequence}\n"
        f"entry_hash: {record.entry_hash}\nhead_hash: {ledger.head_hash()}"
    )
    _emit_success(payload, args.json, stdout, human=human)
    return SUCCESS


def _load_policy_ledger(path: str | Path) -> PolicyDeploymentLedger:
    ledger_path = Path(path)
    if not ledger_path.exists():
        raise CLIError("LEDGER_NOT_FOUND", f"{path}: ledger file not found")
    try:
        # Defer chain verification to callers so they can attach expected_head
        # and emit a single integrity error path.
        return PolicyDeploymentLedger.from_jsonl(ledger_path, verify=False)
    except LedgerIntegrityError as exc:
        raise CLIError("LEDGER_INTEGRITY_ERROR", str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise CLIError("LEDGER_MALFORMED", str(exc)) from exc


def _load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise CLIError("JSON_MALFORMED", f"{path}: JSON could not be read") from exc


def _load_gco(path: str | Path) -> GCO:
    try:
        return GCO.model_validate(_load_json(path))
    except ValidationError as exc:
        raise CLIError(_code(DerivationError.GCO_MALFORMED), str(exc)) from exc


def _load_delegation_request(path: str | Path) -> DelegationRequest:
    try:
        return DelegationRequest.model_validate(_load_json(path))
    except ValidationError as exc:
        raise CLIError(_code(DerivationError.GCO_MALFORMED), str(exc)) from exc


def _load_bundle(path: str | Path) -> TrustBundle:
    try:
        return TrustBundle.from_json_file(path)
    except (TrustBundleError, AttributeError) as exc:
        raise CLIError("TRUST_BUNDLE_MALFORMED", str(exc)) from exc


def _load_signing_authority(path: str | Path, kid: str) -> PemSigningAuthority:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except Exception as exc:  # noqa: BLE001
        raise CLIError("SIGN_KEY_MALFORMED", f"{path}: PEM private key could not be read") from exc
    return PemSigningAuthority(key, kid=kid)


def _schema_path() -> Path:
    candidates = [
        Path(__file__).resolve().parents[2] / "schemas" / "gco_schema_v1.json",
        Path(sys.prefix) / "schemas" / "gco_schema_v1.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise CLIError("SCHEMA_NOT_FOUND", "bundled JSON schema could not be found")


def _verification_checks(result: VerificationResult) -> dict[str, str]:
    if result.verified:
        return {"signature": "pass", "identity": "pass", "digest": "pass", "expiry": "pass"}
    failed = {
        AttestationError.UNVERIFIED_SIGNATURE: "signature",
        AttestationError.UNTRUSTED_KEY: "signature",
        AttestationError.SPIFFE_ID_MISMATCH: "identity",
        AttestationError.GCO_DIGEST_MISMATCH: "digest",
        AttestationError.EXPIRED_ATTESTATION: "expiry",
    }.get(result.error_code)
    checks = {"signature": "unknown", "identity": "unknown", "digest": "unknown", "expiry": "unknown"}
    if failed is not None:
        checks[failed] = "fail"
    return checks


def _inspection_payload(gco: GCO) -> dict[str, Any]:
    return {
        "identity": {
            "gco_version": gco.gco_version,
            "trace_id": str(gco.trace_id),
            "span_id": str(gco.span_id),
            "parent_span_id": str(gco.parent_span_id) if gco.parent_span_id else None,
            "policy_id": gco.policy_id,
            "model_identity": gco.model_identity,
            "intervention_version": gco.intervention_version,
        },
        "tool_authority": [tool.model_dump(mode="json") for tool in gco.tool_authority],
        "state_access_permissions": [permission.model_dump(mode="json") for permission in gco.state_access_permissions],
        "taint_policy": sorted({permission.taint_policy.value for permission in gco.state_access_permissions}),
        "lineage": gco.lineage,
        "expires_at": gco.expires_at.isoformat(),
        "attestation_format": gco.attestation.format.value if gco.attestation else None,
    }


def _format_verify(payload: dict[str, Any]) -> str:
    checks = payload["checks"]
    return "\n".join(
        [
            "allow: attestation verified",
            f"signature: {checks['signature']}",
            f"identity: {checks['identity']}",
            f"digest: {checks['digest']}",
            f"expiry: {checks['expiry']}",
        ]
    )


def _format_inspection(payload: dict[str, Any]) -> str:
    identity = payload["identity"]
    lines = [
        f"identity: {identity['model_identity']}",
        f"trace/span: {identity['trace_id']} / {identity['span_id']}",
        f"parent_span_id: {identity['parent_span_id']}",
        f"policy_id: {identity['policy_id']}",
        "tool authority:",
    ]
    lines.extend(f"  - {tool['tool_uri']} scope={tool['scope']} max_depth={tool['max_depth']}" for tool in payload["tool_authority"])
    lines.append("state permissions:")
    lines.extend(
        f"  - {permission['namespace']} access={permission['access_mode']} taint={permission['taint_policy']}"
        for permission in payload["state_access_permissions"]
    )
    lines.extend(
        [
            f"taint policy: {', '.join(payload['taint_policy']) or 'none'}",
            f"lineage: {len(payload['lineage'])} entries",
            f"expires_at: {payload['expires_at']}",
            f"attestation format: {payload['attestation_format']}",
        ]
    )
    return "\n".join(lines)


def _emit_success(payload: dict[str, Any], as_json: bool, stdout: TextIO, *, human: str) -> None:
    if as_json:
        print(json.dumps({"ok": True, **payload}, sort_keys=True), file=stdout)
    else:
        print(human, file=stdout)


def _emit_failure(
    code: str,
    message: str,
    as_json: bool,
    stdout: TextIO,
    stderr: TextIO,
    *,
    payload: dict[str, Any] | None = None,
    prefix: str = "error",
) -> None:
    body = {"ok": False, "error_code": code, "message": message}
    if payload is not None:
        body.update(payload)
    if as_json:
        print(json.dumps(body, sort_keys=True), file=stdout)
    else:
        print(f"{prefix}: {code}: {message}", file=stderr)


def _code(value: Any) -> str:
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, type):
        return value.__name__
    if value is None:
        return "UNKNOWN"
    return str(value)


def _exception_code(exc: Exception) -> str:
    error = getattr(exc, "error", None)
    return _code(error) if error is not None else "GCO_MALFORMED"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
