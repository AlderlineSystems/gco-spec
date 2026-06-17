from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import AnyHttpUrl, AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class AttestationFormat(str, Enum):
    JWT_SVID = "jwt-svid"
    X509_SVID = "x509-svid"
    RAW_JWS = "raw-jws"
    TPM_QUOTE = "tpm-quote"


class AccessMode(str, Enum):
    NONE = "none"
    READ = "read"
    APPEND = "append"
    WRITE = "write"


class TaintPolicy(str, Enum):
    CLEAN = "clean"
    SANITIZED = "sanitized"
    TAINTED = "tainted"
    ISOLATED = "isolated"


class StrictBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class AttestationModel(StrictBaseModel):
    format: AttestationFormat
    value: str
    issuer: Optional[AnyHttpUrl] = None


class ToolAuthority(StrictBaseModel):
    tool_uri: AnyHttpUrl
    scope: str
    max_depth: int = Field(ge=0)


class StatePermission(StrictBaseModel):
    namespace: str
    access_mode: AccessMode
    taint_policy: TaintPolicy = TaintPolicy.CLEAN


class GCO(StrictBaseModel):
    gco_version: str
    trace_id: UUID
    span_id: UUID
    parent_span_id: Optional[UUID]
    policy_id: str
    model_identity: str
    intervention_version: str
    tool_authority: list[ToolAuthority] = Field(default_factory=list)
    state_access_permissions: list[StatePermission] = Field(default_factory=list)
    expires_at: AwareDatetime
    lineage: list[str] = Field(default_factory=list)
    attestation: Optional[AttestationModel]

    @field_validator("expires_at")
    @classmethod
    def expires_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must be UTC")
        return value
