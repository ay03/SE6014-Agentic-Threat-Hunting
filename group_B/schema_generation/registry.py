"""Versioned file registry for validated B2 schemas.

Layout::

    registry/
      index.json
      schemas/<schema_id>/v<version>.json

Only validated entries are registered. Writes use a temporary file in the
destination directory followed by ``os.replace`` so readers never observe a
partially written JSON document.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from group_B.common.errors import RegistryError
from group_B.schema_generation.models import (
    Provenance,
    SchemaSpec,
    ValidationReport,
    utc_now,
)
from group_B.schema_generation.signature import SourceSignature

_SCHEMA_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_ENTRY_PATH_RE = re.compile(
    r"^schemas/[a-z0-9][a-z0-9._-]{0,63}/v[1-9][0-9]*\.json$"
)
_PIPELINE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def default_registry_root() -> Path:
    """Return the repository-local registry directory."""

    return Path(__file__).resolve().parent / "registry"


class SignatureIndexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: str = Field(pattern=_SCHEMA_ID_RE.pattern)
    version: int = Field(ge=1)
    pipeline_id: str = Field(pattern=_PIPELINE_ID_RE.pattern)
    path: str = Field(pattern=_ENTRY_PATH_RE.pattern)


class RegistryIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1)
    signatures: dict[str, SignatureIndexEntry] = Field(default_factory=dict)

    @field_validator("signatures")
    @classmethod
    def _validate_signature_keys(
        cls,
        value: dict[str, SignatureIndexEntry],
    ) -> dict[str, SignatureIndexEntry]:
        for key in value:
            if not isinstance(key, str) or not _HEX64_RE.fullmatch(key):
                raise ValueError(
                    "signature index keys must be 64-character lowercase hex"
                )
        return value


class RegistryEntry(BaseModel):
    """One validated schema version and its compiled pipeline."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    schema_spec: SchemaSpec = Field(alias="schema")
    signature: SourceSignature
    pipeline: dict[str, Any]
    pipeline_id: str = Field(pattern=_PIPELINE_ID_RE.pattern)
    validation: ValidationReport
    provenance: Provenance
    registered_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_entry(self) -> "RegistryEntry":
        if not self.validation.accepted:
            raise ValueError("registry entry validation must be accepted")
        if self.pipeline_id != self.schema_spec.pipeline_id:
            raise ValueError(
                "pipeline_id must match schema_id and schema version"
            )
        if not self.pipeline:
            raise ValueError("registry entry pipeline must not be empty")
        try:
            json.dumps(self.pipeline, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "registry entry pipeline must be JSON-serializable"
            ) from error
        if (
            self.registered_at.tzinfo is None
            or self.registered_at.utcoffset() is None
        ):
            raise ValueError("registered_at must be timezone-aware")
        return self


class SchemaRegistry:
    """Read and write validated schema entries under one registry root."""

    def __init__(self, root: Path | str | None = None) -> None:
        if root is None:
            self.root = default_registry_root()
        else:
            self.root = Path(root).expanduser().resolve()
        self.schemas_dir = self.root / "schemas"
        self.index_path = self.root / "index.json"

    def register(
        self,
        *,
        schema: SchemaSpec,
        signature: SourceSignature,
        pipeline: dict[str, Any],
        validation: ValidationReport,
        provenance: Provenance,
    ) -> RegistryEntry:
        """Register a validated schema, or return the identical existing one."""

        if not isinstance(schema, SchemaSpec):
            raise RegistryError("schema must be a SchemaSpec")
        if not isinstance(signature, SourceSignature):
            raise RegistryError("signature must be a SourceSignature")
        if not isinstance(validation, ValidationReport):
            raise RegistryError("validation must be a ValidationReport")
        if not isinstance(provenance, Provenance):
            raise RegistryError("provenance must be Provenance")
        if not validation.accepted:
            raise RegistryError("cannot register a rejected schema")
        if not isinstance(pipeline, dict) or not pipeline:
            raise RegistryError("pipeline must be a non-empty dict")

        existing = self.find_by_signature(signature)
        if existing is not None:
            if (
                existing.schema_spec == schema
                and existing.pipeline == pipeline
                and existing.validation == validation
            ):
                return existing
            raise RegistryError(
                "signature is already registered with different content"
            )

        expected_version = self.next_version(schema.schema_id)
        if schema.version != expected_version:
            raise RegistryError(
                f"expected version {expected_version} for "
                f"{schema.schema_id}, got {schema.version}"
            )

        entry = RegistryEntry(
            schema_spec=schema,
            signature=signature,
            pipeline=pipeline,
            pipeline_id=schema.pipeline_id,
            validation=validation,
            provenance=provenance,
        )
        path = self.entry_path(schema.schema_id, schema.version)
        if path.exists():
            raise RegistryError(f"registry entry already exists: {path}")

        self._write_json(path, entry.model_dump(mode="json", by_alias=True))
        index = self._read_index()
        index.signatures[signature.hash] = SignatureIndexEntry(
            schema_id=schema.schema_id,
            version=schema.version,
            pipeline_id=entry.pipeline_id,
            path=self._relative_entry_path(
                schema.schema_id,
                schema.version,
            ),
        )
        self._write_json(self.index_path, index.model_dump(mode="json"))
        return entry

    def find_by_signature(
        self,
        signature: SourceSignature | str,
    ) -> RegistryEntry | None:
        """Return the validated entry for a signature, if one exists."""

        signature_hash = (
            signature.hash
            if isinstance(signature, SourceSignature)
            else signature
        )
        if (
            not isinstance(signature_hash, str)
            or not _HEX64_RE.fullmatch(signature_hash)
        ):
            raise RegistryError(
                "signature hash must be 64 lowercase hex characters"
            )

        if not self.index_path.is_file() and self._has_entries():
            self.rebuild_index()
        index = self._read_index()
        if not index.signatures and self._has_entries():
            self.rebuild_index()
            index = self._read_index()

        item = index.signatures.get(signature_hash)
        if item is None:
            return None

        entry = self._read_entry(item)
        if entry is None:
            self.rebuild_index()
            item = self._read_index().signatures.get(signature_hash)
            if item is None:
                return None
            entry = self._read_entry(item)
        return entry

    def get(self, schema_id: str, version: int) -> RegistryEntry | None:
        """Return one specific schema version, if present."""

        path = self.entry_path(schema_id, version)
        if not path.is_file():
            return None
        return self._read_entry_path(path)

    def latest(self, schema_id: str) -> RegistryEntry | None:
        """Return the highest registered version for a schema id."""

        versions = self._versions(schema_id)
        if not versions:
            return None
        return self.get(schema_id, versions[-1])

    def list_entries(self) -> list[RegistryEntry]:
        """Return all registered entries sorted by schema id and version."""

        if not self.schemas_dir.is_dir():
            return []

        entries: list[RegistryEntry] = []
        for schema_dir in sorted(self.schemas_dir.iterdir()):
            if not schema_dir.is_dir():
                continue
            if not _SCHEMA_ID_RE.fullmatch(schema_dir.name):
                raise RegistryError(
                    f"invalid schema directory: {schema_dir}"
                )
            for version in self._versions(schema_dir.name):
                entry = self.get(schema_dir.name, version)
                if entry is not None:
                    entries.append(entry)
        return entries

    def next_version(self, schema_id: str) -> int:
        """Return the next version number for a schema id."""

        self._validate_schema_id(schema_id)
        versions = self._versions(schema_id)
        return max(versions, default=0) + 1

    def rebuild_index(self) -> RegistryIndex:
        """Rebuild ``index.json`` from the entry files."""

        index = RegistryIndex()
        for entry in self.list_entries():
            if entry.signature.hash in index.signatures:
                raise RegistryError(
                    "duplicate signature found while rebuilding index"
                )
            index.signatures[entry.signature.hash] = SignatureIndexEntry(
                schema_id=entry.schema_spec.schema_id,
                version=entry.schema_spec.version,
                pipeline_id=entry.pipeline_id,
                path=self._relative_entry_path(
                    entry.schema_spec.schema_id,
                    entry.schema_spec.version,
                ),
            )
        self._write_json(self.index_path, index.model_dump(mode="json"))
        return index

    def entry_path(self, schema_id: str, version: int) -> Path:
        """Return the on-disk path for one schema version."""

        self._validate_schema_id(schema_id)
        self._validate_version(version)
        return self.schemas_dir / schema_id / f"v{version}.json"

    def _relative_entry_path(self, schema_id: str, version: int) -> str:
        self._validate_schema_id(schema_id)
        self._validate_version(version)
        return f"schemas/{schema_id}/v{version}.json"

    def _versions(self, schema_id: str) -> list[int]:
        self._validate_schema_id(schema_id)
        schema_dir = self.schemas_dir / schema_id
        if not schema_dir.is_dir():
            return []

        versions: list[int] = []
        for path in schema_dir.iterdir():
            match = re.fullmatch(r"v([1-9][0-9]*)\.json", path.name)
            if match and path.is_file():
                versions.append(int(match.group(1)))
        return sorted(versions)

    def _has_entries(self) -> bool:
        if not self.schemas_dir.is_dir():
            return False
        for schema_dir in self.schemas_dir.iterdir():
            if schema_dir.is_dir() and any(schema_dir.glob("v*.json")):
                return True
        return False

    def _read_index(self) -> RegistryIndex:
        if not self.index_path.is_file():
            return RegistryIndex()
        data = self._read_json(self.index_path)
        try:
            return RegistryIndex.model_validate(data)
        except ValidationError as error:
            raise RegistryError(
                f"invalid registry index {self.index_path}: {error}"
            ) from error

    def _read_entry(
        self,
        item: SignatureIndexEntry,
    ) -> RegistryEntry | None:
        path = self._resolve_index_path(item.path)
        if not path.is_file():
            return None
        entry = self._read_entry_path(path)
        if (
            entry.schema_spec.schema_id != item.schema_id
            or entry.schema_spec.version != item.version
            or entry.pipeline_id != item.pipeline_id
        ):
            raise RegistryError(
                "registry index does not match stored entry"
            )
        return entry

    def _read_entry_path(self, path: Path) -> RegistryEntry:
        self._ensure_within_schemas(path)
        data = self._read_json(path)
        try:
            entry = RegistryEntry.model_validate(data)
        except ValidationError as error:
            raise RegistryError(
                f"invalid registry entry {path}: {error}"
            ) from error

        expected = self.entry_path(
            entry.schema_spec.schema_id,
            entry.schema_spec.version,
        )
        if path.resolve() != expected.resolve():
            raise RegistryError(
                "registry entry path does not match schema id/version: "
                f"{path}"
            )
        return entry

    def _resolve_index_path(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve()
        self._ensure_within_schemas(candidate)
        return candidate

    def _ensure_within_schemas(self, path: Path) -> None:
        schemas_root = self.schemas_dir.resolve()
        if not path.resolve().is_relative_to(schemas_root):
            raise RegistryError(
                f"registry path escapes schemas directory: {path}"
            )

    @staticmethod
    def _validate_schema_id(schema_id: str) -> None:
        if (
            not isinstance(schema_id, str)
            or not _SCHEMA_ID_RE.fullmatch(schema_id)
        ):
            raise RegistryError(f"invalid schema_id: {schema_id!r}")

    @staticmethod
    def _validate_version(version: int) -> None:
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version < 1
        ):
            raise RegistryError("version must be a positive integer")

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            with path.open("r", encoding="utf-8") as stream:
                return json.load(stream)
        except (OSError, json.JSONDecodeError) as error:
            raise RegistryError(
                f"could not read registry file {path}: {error}"
            ) from error

    @staticmethod
    def _write_json(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        except (OSError, TypeError, ValueError) as error:
            temp_path.unlink(missing_ok=True)
            raise RegistryError(
                f"could not write registry file {path}: {error}"
            ) from error
