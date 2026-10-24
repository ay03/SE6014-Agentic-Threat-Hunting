"""Deterministic structural signatures for source records.

The signature deliberately ignores field values and keeps only structure:
column counts and headers for CSV, key paths and types for JSON, key names for
key-value records, and a small token-shape fallback for arbitrary lines.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

SIGNATURE_VERSION = 1
DEFAULT_MAX_SAMPLE_LINES = 50

_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_KV_RE = re.compile(
    r'(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)='
    r'(?P<value>"[^"]*"|[^\s]+)'
)


class SignatureKind(str, Enum):
    EMPTY = "empty"
    JSON = "json"
    CSV = "csv"
    KV = "kv"
    LINE = "line"


def _signature_hash(
    version: int,
    kind: SignatureKind,
    shape: dict[str, Any],
) -> str:
    payload = {
        "version": version,
        "kind": kind.value,
        "shape": shape,
    }
    try:
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("signature shape must be JSON-serializable") from error
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SourceSignature(BaseModel):
    """Stable identity for a source's record structure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=SIGNATURE_VERSION, ge=1)
    kind: SignatureKind
    shape: dict[str, Any]
    sample_count: int = Field(ge=0)
    hash: str = Field(pattern=_HEX64_RE.pattern)

    @model_validator(mode="after")
    def _validate_hash(self) -> "SourceSignature":
        expected = _signature_hash(self.version, self.kind, self.shape)
        if self.hash != expected:
            raise ValueError("signature hash does not match its content")
        return self


def _json_paths(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(value, dict):
        if not value:
            paths.add(f"{prefix}:object" if prefix else ":object")
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            paths.update(_json_paths(item, path))
    elif isinstance(value, list):
        paths.add(f"{prefix}:array")
        for item in value:
            paths.update(_json_paths(item, prefix + "[]"))
    elif value is None:
        paths.add(f"{prefix}:null")
    elif isinstance(value, bool):
        paths.add(f"{prefix}:boolean")
    elif isinstance(value, int):
        paths.add(f"{prefix}:integer")
    elif isinstance(value, float):
        paths.add(f"{prefix}:float")
    else:
        paths.add(f"{prefix}:string")
    return paths


def _json_shape(lines: list[str]) -> dict[str, Any] | None:
    paths: set[str] = set()
    top_level: set[str] = set()
    for line in lines:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(value, dict):
            return None
        top_level.update(value.keys())
        paths.update(_json_paths(value))
    return {
        "top_level_keys": sorted(top_level),
        "paths": sorted(paths),
    }


def _normalize_header(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return normalized or "column"


def _csv_shape(lines: list[str]) -> dict[str, Any] | None:
    best: tuple[tuple[int, int], str, list[list[str]]] | None = None
    for delimiter in (",", "\t", "|", ";"):
        try:
            rows = list(csv.reader(lines, delimiter=delimiter))
        except csv.Error:
            continue
        if len(rows) < 2:
            continue
        widths = {len(row) for row in rows}
        if len(widths) != 1:
            continue
        width = widths.pop()
        if width < 2:
            continue
        score = (width, len(rows))
        if best is None or score > best[0]:
            best = (score, delimiter, rows)

    if best is None:
        return None

    _, delimiter, rows = best
    has_header = False
    try:
        has_header = csv.Sniffer().has_header("\n".join(lines))
    except csv.Error:
        has_header = False

    header = (
        [_normalize_header(cell) for cell in rows[0]]
        if has_header
        else []
    )
    return {
        "delimiter": delimiter,
        "columns": len(rows[0]),
        "has_header": has_header,
        "header": header,
    }


def _kv_shape(lines: list[str]) -> dict[str, Any] | None:
    keys_by_line: list[list[str]] = []
    for line in lines:
        keys = [match.group("key") for match in _KV_RE.finditer(line)]
        if len(keys) < 2:
            return None
        keys_by_line.append(keys)

    all_keys = sorted({key for keys in keys_by_line for key in keys})
    common = set(keys_by_line[0])
    for keys in keys_by_line[1:]:
        common.intersection_update(keys)

    return {
        "keys": all_keys,
        "common_keys": sorted(common),
        "min_keys": min(len(keys) for keys in keys_by_line),
        "max_keys": max(len(keys) for keys in keys_by_line),
    }


def _mask_token(token: str) -> str:
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
        return "<ip>"
    if re.fullmatch(r"\d+", token):
        return "<int>"
    if re.fullmatch(r"\d+\.\d+", token):
        return "<float>"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        token,
    ):
        return "<uuid>"
    if re.fullmatch(r"[0-9a-fA-F]{8,}", token):
        return "<hex>"
    if token.startswith('"') and token.endswith('"'):
        return "<quoted>"
    return token


def _line_shape(lines: list[str]) -> dict[str, Any]:
    token_counts = sorted({len(line.split()) for line in lines})
    first_tokens = sorted(
        {_mask_token(line.split()[0]) for line in lines if line.split()}
    )
    return {
        "token_counts": token_counts,
        "first_tokens": first_tokens,
        "has_equals": all("=" in line for line in lines),
        "has_colon": all(":" in line for line in lines),
    }


def _make_signature(
    kind: SignatureKind,
    shape: dict[str, Any],
    sample_count: int,
) -> SourceSignature:
    return SourceSignature(
        version=SIGNATURE_VERSION,
        kind=kind,
        shape=shape,
        sample_count=sample_count,
        hash=_signature_hash(SIGNATURE_VERSION, kind, shape),
    )


def build_signature(
    lines: Iterable[str],
    *,
    max_lines: int = DEFAULT_MAX_SAMPLE_LINES,
) -> SourceSignature:
    """Build a deterministic structural signature from raw source lines."""

    if isinstance(lines, (str, bytes)):
        raise TypeError("lines must be an iterable of strings, not one string")
    if max_lines < 1:
        raise ValueError("max_lines must be at least 1")

    sample: list[str] = []
    for raw_line in lines:
        if not isinstance(raw_line, str):
            raise TypeError("every source line must be a string")
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        sample.append(line)
        if len(sample) >= max_lines:
            break

    if not sample:
        return _make_signature(SignatureKind.EMPTY, {}, 0)

    json_shape = _json_shape(sample)
    if json_shape is not None:
        return _make_signature(
            SignatureKind.JSON,
            json_shape,
            len(sample),
        )

    csv_shape = _csv_shape(sample)
    if csv_shape is not None:
        return _make_signature(
            SignatureKind.CSV,
            csv_shape,
            len(sample),
        )

    kv_shape = _kv_shape(sample)
    if kv_shape is not None:
        return _make_signature(
            SignatureKind.KV,
            kv_shape,
            len(sample),
        )

    return _make_signature(
        SignatureKind.LINE,
        _line_shape(sample),
        len(sample),
    )
