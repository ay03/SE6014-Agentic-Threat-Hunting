"""Declarative schema models for B2 unknown-schema generation.

The models describe a parser and the ECS fields it produces. They contain no
executable code. Batch 2 compiles a validated ``SchemaSpec`` into an
Elasticsearch ingest pipeline.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

_SCHEMA_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""

    return datetime.now(timezone.utc)


class FieldType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    IP = "ip"
    ARRAY = "array"


class CsvParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["csv"] = "csv"
    delimiter: str = Field(default=",", min_length=1, max_length=1)
    quotechar: str = Field(default='"', min_length=1, max_length=1)
    has_header: bool = True


class JsonParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["json"] = "json"


class KvParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["kv"] = "kv"
    field_split: str = Field(default=" ", min_length=1, max_length=8)
    value_split: str = Field(default="=", min_length=1, max_length=8)


class DissectParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["dissect"] = "dissect"
    pattern: str = Field(min_length=1, max_length=2048)


class GrokParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["grok"] = "grok"
    pattern: str = Field(min_length=1, max_length=2048)


class RegexParser(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["regex"] = "regex"
    pattern: str = Field(min_length=1, max_length=2048)


ParserSpec = Annotated[
    Union[
        CsvParser,
        JsonParser,
        KvParser,
        DissectParser,
        GrokParser,
        RegexParser,
    ],
    Field(discriminator="kind"),
]


class FieldSpec(BaseModel):
    """One ECS field produced by the parser.

    Exactly one of ``source`` or ``constant`` must be set. ``source`` is a
    parser-specific reference such as a CSV column, JSON path, or capture
    group. ``$raw`` is reserved for the original raw record.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: str = Field(
        pattern=r"^[@A-Za-z0-9_][A-Za-z0-9_.@-]*$",
        max_length=255,
    )
    source: str | None = Field(default=None, max_length=255)
    constant: Any = None
    type: FieldType = FieldType.STRING
    required: bool = False
    format: str | None = Field(default=None, max_length=128)
    timezone: str | None = Field(default=None, max_length=64)

    @field_validator("constant")
    @classmethod
    def _validate_constant(cls, value: Any) -> Any:
        if value is None:
            return None
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("constant must be a JSON value") from error
        return value

    @field_validator("target", "source", "format", "timezone", mode="before")
    @classmethod
    def _clean_text(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None

    @model_validator(mode="after")
    def _validate_source_or_constant(self) -> "FieldSpec":
        if self.source is None and self.constant is None:
            raise ValueError("field must set source or constant")
        if self.source is not None and self.constant is not None:
            raise ValueError("field cannot set both source and constant")
        if self.type is not FieldType.DATETIME:
            if self.format is not None:
                raise ValueError("format is only valid for datetime fields")
            if self.timezone is not None:
                raise ValueError("timezone is only valid for datetime fields")
        return self


class TimestampSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(min_length=1, max_length=255)
    formats: list[str] = Field(
        default_factory=lambda: ["ISO8601"],
        min_length=1,
        max_length=10,
    )
    timezone: str | None = Field(default=None, max_length=64)
    target: Literal["@timestamp"] = "@timestamp"

    @field_validator("source", "timezone", mode="before")
    @classmethod
    def _clean_text(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        cleaned = value.strip()
        return cleaned or None

    @field_validator("formats", mode="before")
    @classmethod
    def _clean_formats(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            raise ValueError("formats must be a list of strings")
        cleaned = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("formats must contain strings")
            item = item.strip()
            if item:
                cleaned.append(item)
        if not cleaned:
            raise ValueError("formats must not be empty")
        return cleaned


class SchemaSpec(BaseModel):
    """A declarative parser and ECS field mapping for one dataset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: str = Field(pattern=_SCHEMA_ID_RE.pattern)
    version: int = Field(default=1, ge=1)
    dataset: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    parser: ParserSpec
    timestamp: TimestampSpec
    fields: list[FieldSpec] = Field(min_length=1)

    @field_validator("schema_id", "dataset", mode="before")
    @classmethod
    def _clean_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        return value.strip()

    @model_validator(mode="after")
    def _validate_required_fields(self) -> "SchemaSpec":
        targets = [field.target for field in self.fields]
        if len(targets) != len(set(targets)):
            raise ValueError("field targets must be unique")

        if "@timestamp" in targets:
            raise ValueError(
                "@timestamp is produced by timestamp, not a field entry"
            )

        missing = {
            "event.dataset",
            "event.original",
            "message",
        } - set(targets)
        if missing:
            raise ValueError(
                "schema is missing required fields: "
                + ", ".join(sorted(missing))
            )

        original = next(
            field for field in self.fields
            if field.target == "event.original"
        )
        if original.source != "$raw":
            raise ValueError("event.original must use source '$raw'")

        dataset_field = next(
            field for field in self.fields
            if field.target == "event.dataset"
        )
        if dataset_field.constant is not None:
            if (
                not isinstance(dataset_field.constant, str)
                or dataset_field.constant.strip() != self.dataset
            ):
                raise ValueError(
                    "event.dataset constant must match schema dataset"
                )

        message_field = next(
            field for field in self.fields
            if field.target == "message"
        )
        if message_field.constant is not None:
            if (
                not isinstance(message_field.constant, str)
                or not message_field.constant.strip()
            ):
                raise ValueError("message constant must be non-empty")

        for field in self.fields:
            if (
                field.target == "event.category"
                and field.type is not FieldType.ARRAY
            ):
                raise ValueError(
                    "event.category must use the array field type"
                )

        return self

    @property
    def pipeline_id(self) -> str:
        prefix = "" if self.schema_id.startswith("b2-") else "b2-"
        return f"{prefix}{self.schema_id}-v{self.version}"


class ValidationReport(BaseModel):
    """Result of validating a candidate schema against sample records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["offline", "es_simulate"] = "offline"
    accepted: bool
    sample_count: int = Field(ge=0)
    available_sample_count: int | None = Field(default=None, ge=0)
    required_field_rate: float = Field(ge=0.0, le=1.0)
    timestamp_parse_rate: float = Field(ge=0.0, le=1.0)
    type_error_count: int = Field(ge=0)
    parse_failure_count: int = Field(default=0, ge=0)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_gate(self) -> "ValidationReport":
        if (
            self.available_sample_count is not None
            and self.sample_count > self.available_sample_count
        ):
            raise ValueError(
                "sample_count cannot exceed available_sample_count"
            )
        if self.parse_failure_count > self.sample_count:
            raise ValueError(
                "parse_failure_count cannot exceed sample_count"
            )
        if self.accepted:
            if self.sample_count < 1:
                raise ValueError("accepted schema needs at least 1 sample")
            if self.available_sample_count is None:
                minimum_samples = 5
            else:
                minimum_samples = min(5, self.available_sample_count)
            if self.sample_count < minimum_samples:
                raise ValueError(
                    "accepted schema needs at least 5 samples, or every "
                    "available sample when fewer than 5 exist"
                )
            if self.required_field_rate < 1.0:
                raise ValueError(
                    "accepted schema needs a 100% required-field rate"
                )
            if self.timestamp_parse_rate < 1.0:
                raise ValueError(
                    "accepted schema needs a 100% timestamp parse rate"
                )
            if self.type_error_count != 0:
                raise ValueError(
                    "accepted schema cannot have type errors"
                )
            if self.parse_failure_count >= self.sample_count:
                raise ValueError(
                    "accepted schema needs at least one parsed sample"
                )
            if self.errors:
                raise ValueError(
                    "accepted schema cannot include validation errors"
                )
        elif not self.errors:
            raise ValueError("rejected schema must include errors")
        return self


class Provenance(BaseModel):
    """Repeatability metadata stored with a registered schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    generator: Literal["heuristic", "llm", "manual"] = "heuristic"
    model: str | None = Field(default=None, max_length=128)
    model_version: str | None = Field(default=None, max_length=128)
    prompt_hash: str | None = Field(
        default=None,
        pattern=_HEX64_RE.pattern,
    )
    prompt_template: str | None = Field(default=None, max_length=4096)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    seed: int | None = None
    sample_hashes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("sample_hashes")
    @classmethod
    def _validate_sample_hashes(cls, value: list[str]) -> list[str]:
        for item in value:
            if not isinstance(item, str) or not _HEX64_RE.fullmatch(item):
                raise ValueError(
                    "sample_hashes must be 64-character lowercase hex"
                )
        return value

    @model_validator(mode="after")
    def _validate_provenance(self) -> "Provenance":
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if self.generator == "llm":
            if not self.model:
                raise ValueError("llm provenance requires a model")
            if not self.prompt_hash:
                raise ValueError("llm provenance requires a prompt_hash")
            if not self.sample_hashes:
                raise ValueError("llm provenance requires sample_hashes")
        return self
