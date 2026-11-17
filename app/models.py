"""Pydantic models and zone validation rules shared by both roles."""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import settings

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def _ipv4(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value}") from exc
    if ip.version != 4:
        raise ValueError("only IPv4 A records are supported")
    return str(ip)


class ViewRuleInput(BaseModel):
    """One CIDR -> IPv4 site-selection rule attached to a record name."""

    cidr: str = Field(..., examples=["10.1.0.0/16"])
    ip: str = Field(..., examples=["10.1.0.1"])

    @field_validator("cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("cidr must be a string")
        try:
            net = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {v}") from exc
        if net.version != 4:
            raise ValueError("only IPv4 CIDR rules are supported")
        if net.prefixlen == 0:
            raise ValueError(
                "0.0.0.0/0 is not a valid rule: use the record's "
                "default ip for the catch-all answer"
            )
        return str(net)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return _ipv4(v)


class RecordInput(BaseModel):
    name: str = Field(..., examples=["db.internal.local"])
    ip: str = Field(..., examples=["10.0.0.11"])
    rules: List[ViewRuleInput] = Field(
        default_factory=list,
        description=(
            "Optional CIDR -> IPv4 site-selection rules. Overlaps are "
            "resolved by longest-prefix match; clients outside every "
            "rule get the default ip."
        ),
    )

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        if not isinstance(v, str):
            raise ValueError("name must be a string")
        return v.strip().rstrip(".").lower()

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return _ipv4(v)

    @model_validator(mode="after")
    def _check_rules(self) -> "RecordInput":
        if len(self.rules) > settings.max_view_rules:
            raise ValueError(
                f"a name may carry at most {settings.max_view_rules} "
                "CIDR rules"
            )
        cidrs = [r.cidr for r in self.rules]
        if len(set(cidrs)) != len(cidrs):
            raise ValueError("duplicate CIDR rule on the same name")
        return self


class ZonePayload(BaseModel):
    """A complete replacement of the fixed zone (max 8 A records).

    Each record keeps its classic default IPv4 and may additionally
    carry up to ``MAX_VIEW_RULES`` CIDR -> IPv4 site-selection rules.
    """

    records: List[RecordInput]

    @model_validator(mode="after")
    def _validate_zone(self) -> "ZonePayload":
        if not self.records:
            raise ValueError("zone must contain at least one A record")
        if len(self.records) > settings.max_records:
            raise ValueError(
                f"a zone may contain at most {settings.max_records} A records"
            )
        zone = settings.dns_zone.rstrip(".").lower()
        suffix = "." + zone
        seen: set[str] = set()
        for rec in self.records:
            name = rec.name
            if name != zone and not name.endswith(suffix):
                raise ValueError(
                    f"record {name!r} is outside the fixed zone {zone!r}"
                )
            owner = name[: -len(suffix)] if name.endswith(suffix) else ""
            labels = owner.split(".") if owner else []
            if any(not _LABEL.match(label) for label in labels):
                raise ValueError(f"invalid owner name: {name!r}")
            if name in seen:
                raise ValueError(f"duplicate A record name: {name!r}")
            seen.add(name)
        return self

    def sorted_records(self) -> List[RecordInput]:
        return sorted(self.records, key=lambda r: r.name)


class ViewRuleOut(BaseModel):
    cidr: str
    ip: str


class RecordOut(BaseModel):
    name: str
    ip: str
    rules: List[ViewRuleOut] = []


class ZoneOut(BaseModel):
    zone: str
    serial: int
    records: List[RecordOut]
    published_at: Optional[str] = None


class VersionOut(BaseModel):
    role: str
    zone: str
    serial: int
    record_count: int
    published_at: Optional[str] = None
    last_sync_at: Optional[str] = None
    last_sync_status: str = "never"
    last_sync_error: Optional[str] = None
    upstream_serial: Optional[int] = None


class PublishResult(BaseModel):
    ok: bool
    serial: int
    record_count: int
    published_at: str
