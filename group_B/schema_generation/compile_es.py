"""Compile declarative ``SchemaSpec`` objects into Elasticsearch pipelines.

The compiler uses only the processors allowed by ``group_B/CONTRACTS.md``.
Elasticsearch has a native ``csv`` processor, but it is not on the positive
allowlist, so CSV sources are compiled to a bounded ``grok`` expression. The
CSV expression needs the source's header or first row to know the column order;
callers therefore pass representative samples when compiling a CSV schema.

The generated pipeline always starts by preserving the raw line in
``event.original`` and ends with an ``on_failure`` branch that keeps the four
required fields, tags the record with ``_parse_failure`` and records
``error.message``.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from group_B.common.errors import SchemaGenerationError, SchemaValidationError
from group_B.schema_generation.models import (
    CsvParser,
    DissectParser,
    FieldSpec,
    FieldType,
    GrokParser,
    JsonParser,
    KvParser,
    RegexParser,
    SchemaSpec,
    TimestampSpec,
)

ALLOWED_PROCESSORS = frozenset(
    {
        "set",
        "rename",
        "remove",
        "grok",
        "dissect",
        "date",
        "convert",
        "json",
        "kv",
        "user_agent",
        "uri_parts",
        "lowercase",
        "uppercase",
        "trim",
        "split",
        "join",
        "append",
        "gsub",
        "drop",
        "fail",
        "on_failure",
    }
)

FORBIDDEN_PROCESSORS = frozenset(
    {
        "script",
        "foreach",
        "pipeline",
        "reroute",
        "attachment",
        "date_index_name",
        "enrich",
    }
)

MAX_PATTERN_LENGTH = 2048
MAX_SAMPLE_LINE_LENGTH = 65536
TEMP_RAW_FIELD = "b2_raw"
TEMP_OBJECT_FIELD = "b2_tmp"
CSV_FIELD_DEFINITION = "B2_CSV_FIELD"
PARSE_FAILURE_TAG = "_parse_failure"
PARSE_FAILURE_MESSAGE = "Failed to parse source record"
REQUIRED_FIELDS = (
    "@timestamp",
    "event.dataset",
    "event.original",
    "message",
)


class PipelineCompileError(SchemaGenerationError):
    """The declarative schema cannot be compiled safely."""

    code = "PIPELINE_COMPILE_FAILED"


class PipelineSafetyError(SchemaValidationError):
    """A generated or supplied pipeline violates the processor allowlist."""

    code = "PIPELINE_SAFETY_FAILED"


@dataclass(frozen=True)
class PipelineLayout:
    """Parser-specific references used by the compiler and validator."""

    parser_kind: str
    source_paths: dict[str, str]
    timestamp_source_path: str
    cleanup_fields: tuple[str, ...]
    pattern: str | None = None
    pattern_definitions: dict[str, str] | None = None
    csv_header: tuple[str, ...] | None = None
    csv_columns: int | None = None


def build_pipeline_layout(
    schema: SchemaSpec,
    *,
    samples: Sequence[str] | None = None,
) -> PipelineLayout:
    """Build parser references and capture names for a schema."""

    if not isinstance(schema, SchemaSpec):
        raise PipelineCompileError("schema must be a SchemaSpec")
    _validate_timestamp_spec(schema.timestamp)
    for field in schema.fields:
        _validate_field_spec(field)

    parser = schema.parser
    if isinstance(parser, CsvParser):
        return _build_csv_layout(schema, parser, samples)
    if isinstance(parser, JsonParser):
        return _build_object_layout(schema, "json")
    if isinstance(parser, KvParser):
        return _build_object_layout(schema, "kv")
    if isinstance(parser, DissectParser):
        return _build_dissect_layout(schema, parser)
    if isinstance(parser, GrokParser):
        return _build_grok_layout(schema, parser)
    if isinstance(parser, RegexParser):
        return _build_regex_layout(schema, parser)
    raise PipelineCompileError(f"unsupported parser: {parser!r}")


def compile_pipeline(
    schema: SchemaSpec,
    *,
    samples: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Compile ``schema`` into a deterministic Elasticsearch ingest pipeline.

    ``samples`` is required for CSV schemas because the declarative model does
    not store a header. The samples are used only to infer column order and
    count; raw sample values are never copied into the pipeline.
    """

    layout = build_pipeline_layout(schema, samples=samples)
    processors: list[dict[str, Any]] = [
        {
            "set": {
                "field": TEMP_RAW_FIELD,
                "copy_from": "message",
                "override": True,
            }
        },
        {
            "set": {
                "field": "event.original",
                "copy_from": TEMP_RAW_FIELD,
                "override": True,
            }
        },
        {
            "set": {
                "field": "event.dataset",
                "value": schema.dataset,
                "override": True,
            }
        },
    ]

    processors.extend(_parser_processors(schema, layout))
    processors.extend(_timestamp_processors(schema, layout))
    processors.extend(_field_processors(schema, layout))
    processors.extend(_cleanup_processors(layout))

    on_failure: list[dict[str, Any]] = [
        {
            "set": {
                "field": "@timestamp",
                "value": "{{{_ingest.timestamp}}}",
                "override": True,
            }
        },
        {
            "set": {
                "field": "event.dataset",
                "value": schema.dataset,
                "override": True,
            }
        },
        {
            "set": {
                "field": "event.original",
                "copy_from": TEMP_RAW_FIELD,
                "override": True,
            },
            "ignore_failure": True,
        },
        {
            "set": {
                "field": "message",
                "value": PARSE_FAILURE_MESSAGE,
                "override": True,
            }
        },
        {
            "append": {
                "field": "tags",
                "value": PARSE_FAILURE_TAG,
                "allow_duplicates": False,
            }
        },
        {
            "set": {
                "field": "error.message",
                "value": "{{{_ingest.on_failure_message}}}",
                "override": True,
            }
        },
    ]
    on_failure.extend(_cleanup_processors(layout))

    pipeline: dict[str, Any] = {
        "description": (
            f"B2 pipeline for {schema.schema_id} v{schema.version}"
        ),
        "processors": processors,
        "on_failure": on_failure,
    }
    try:
        json.dumps(pipeline, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise PipelineCompileError(
            "compiled pipeline is not JSON-serializable"
        ) from error

    # Imported lazily so compile_es and validate can expose separate APIs
    # without a module-level circular import.
    from group_B.schema_generation.validate import validate_pipeline_safety

    validate_pipeline_safety(pipeline)
    return pipeline


def _validate_field_spec(field: FieldSpec) -> None:
    _validate_target_path(field.target)
    if field.source is not None and field.source != "$raw":
        _validate_source_path(field.source)
    if field.timezone is not None:
        _validate_timezone(field.timezone)
    _validate_constant_type(field)


def _validate_timestamp_spec(timestamp: TimestampSpec) -> None:
    if timestamp.source != "$raw":
        _validate_source_path(timestamp.source)
    if timestamp.timezone is not None:
        _validate_timezone(timestamp.timezone)
    if "auditd" in timestamp.formats and timestamp.formats != ["auditd"]:
        raise PipelineCompileError(
            "the auditd timestamp format cannot be combined with other formats"
        )


def _validate_timezone(value: str) -> None:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise PipelineCompileError(f"unknown timezone: {value!r}") from error


def _validate_target_path(path: str) -> None:
    if not path or path.startswith(("_", "@")):
        raise PipelineCompileError(f"unsafe field target: {path!r}")
    if "@" in path or ".." in path or "*" in path:
        raise PipelineCompileError(f"unsafe field target: {path!r}")
    if any(part == "" for part in path.split(".")):
        raise PipelineCompileError(f"invalid field target: {path!r}")


def _validate_source_path(path: str) -> None:
    if not path or path.startswith(("_", "@")):
        raise PipelineCompileError(f"unsafe source reference: {path!r}")
    if ".." in path or "*" in path:
        raise PipelineCompileError(f"unsafe source reference: {path!r}")
    if any(part == "" for part in path.split(".")):
        raise PipelineCompileError(f"invalid source reference: {path!r}")


def _validate_constant_type(field: FieldSpec) -> None:
    value = field.constant
    if value is None:
        return
    field_type = field.type
    if field_type is FieldType.STRING:
        valid = isinstance(value, str)
    elif field_type is FieldType.INTEGER:
        valid = isinstance(value, int) and not isinstance(value, bool)
    elif field_type is FieldType.FLOAT:
        valid = (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )
    elif field_type is FieldType.BOOLEAN:
        valid = isinstance(value, bool)
    elif field_type is FieldType.ARRAY:
        valid = isinstance(value, list)
    elif field_type is FieldType.IP:
        valid = isinstance(value, str)
        if valid:
            import ipaddress

            try:
                ipaddress.ip_address(value)
            except ValueError:
                valid = False
    elif field_type is FieldType.DATETIME:
        valid = isinstance(value, str)
    else:
        valid = False
    if not valid:
        raise PipelineCompileError(
            f"constant for {field.target!r} does not match "
            f"type {field.type.value!r}"
        )


def _coerce_samples(samples: Sequence[str] | None) -> list[str] | None:
    if samples is None:
        return None
    if isinstance(samples, (str, bytes)):
        raise PipelineCompileError(
            "samples must be a sequence of strings, not one string"
        )
    cleaned: list[str] = []
    for line in samples:
        if not isinstance(line, str):
            raise PipelineCompileError("every sample line must be a string")
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        if len(line) > MAX_SAMPLE_LINE_LENGTH:
            raise PipelineCompileError(
                "sample line exceeds the configured input bound"
            )
        cleaned.append(line)
    return cleaned


def _clean_text(value: str) -> str:
    return value.lstrip("\ufeff").strip()


def _build_object_layout(schema: SchemaSpec, parser_kind: str) -> PipelineLayout:
    source_paths: dict[str, str] = {"$raw": TEMP_RAW_FIELD}
    for field in schema.fields:
        if field.source is None or field.source == "$raw":
            continue
        source_paths[field.source] = f"{TEMP_OBJECT_FIELD}.{field.source}"
    timestamp_source = schema.timestamp.source
    if timestamp_source == "$raw":
        timestamp_path = TEMP_RAW_FIELD
    else:
        timestamp_path = f"{TEMP_OBJECT_FIELD}.{timestamp_source}"
    return PipelineLayout(
        parser_kind=parser_kind,
        source_paths=source_paths,
        timestamp_source_path=timestamp_path,
        cleanup_fields=(TEMP_OBJECT_FIELD,),
    )


def _build_csv_layout(
    schema: SchemaSpec,
    parser: CsvParser,
    samples: Sequence[str] | None,
) -> PipelineLayout:
    cleaned = _coerce_samples(samples)
    if not cleaned:
        raise PipelineCompileError(
            "CSV compilation requires representative samples to infer "
            "the header or column count"
        )

    rows: list[list[str]] = []
    for line in cleaned:
        try:
            row = next(
                csv.reader(
                    [line],
                    delimiter=parser.delimiter,
                    quotechar=parser.quotechar,
                )
            )
        except (csv.Error, StopIteration) as error:
            raise PipelineCompileError(
                "could not parse a CSV sample line"
            ) from error
        rows.append(row)

    if not rows:
        raise PipelineCompileError("CSV compilation received no samples")

    if parser.has_header:
        header = tuple(_clean_text(cell) for cell in rows[0])
        if not header or any(not cell for cell in header):
            raise PipelineCompileError("CSV header contains an empty column")
        if len(set(header)) != len(header):
            raise PipelineCompileError("CSV header contains duplicate columns")
        columns = len(header)
    else:
        header = None
        columns = len(rows[0])
        if columns < 1:
            raise PipelineCompileError("CSV source has no columns")

    source_paths: dict[str, str] = {"$raw": TEMP_RAW_FIELD}
    for field in schema.fields:
        if field.source is None or field.source == "$raw":
            continue
        index = _csv_source_index(field.source, header, columns)
        source_paths[field.source] = f"b2c{index}"

    timestamp_source = schema.timestamp.source
    if timestamp_source == "$raw":
        timestamp_path = TEMP_RAW_FIELD
    else:
        timestamp_path = f"b2c{_csv_source_index(timestamp_source, header, columns)}"

    capture_paths = tuple(f"b2c{index}" for index in range(columns))
    pattern = "^" + _regex_literal(parser.delimiter).join(
        f"%{{{CSV_FIELD_DEFINITION}:{capture_paths[index]}}}"
        for index in range(columns)
    ) + "$"
    pattern_definitions = {
        CSV_FIELD_DEFINITION: _csv_field_regex(parser)
    }
    return PipelineLayout(
        parser_kind="csv",
        source_paths=source_paths,
        timestamp_source_path=timestamp_path,
        cleanup_fields=capture_paths,
        pattern=pattern,
        pattern_definitions=pattern_definitions,
        csv_header=header,
        csv_columns=columns,
    )


def _csv_source_index(
    source: str,
    header: tuple[str, ...] | None,
    columns: int,
) -> int:
    if source.isdigit():
        index = int(source)
    elif source.startswith("column_") and source[7:].isdigit():
        index = int(source[7:])
    elif header is not None and source in header:
        index = header.index(source)
    else:
        raise PipelineCompileError(
            f"CSV source {source!r} is not a header or column index"
        )
    if index < 0 or index >= columns:
        raise PipelineCompileError(
            f"CSV source {source!r} is outside the {columns}-column row"
        )
    return index


def _csv_field_regex(parser: CsvParser) -> str:
    quote = _regex_literal(parser.quotechar)
    delimiter = _regex_literal(parser.delimiter)
    return (
        rf"(?:{quote}(?:[^{quote}]|{quote}{quote})*{quote}"
        rf"|[^{delimiter}\n]*)"
    )


def _regex_literal(value: str) -> str:
    if value == "\t":
        return r"\t"
    if value == "\n":
        return r"\n"
    if value == "\r":
        return r"\r"
    return re.escape(value)


def _build_dissect_layout(
    schema: SchemaSpec,
    parser: DissectParser,
) -> PipelineLayout:
    rewritten, mapping = _rewrite_dissect_pattern(parser.pattern)
    source_paths = _mapped_source_paths(schema, mapping)
    timestamp_source = schema.timestamp.source
    if timestamp_source == "$raw":
        timestamp_path = TEMP_RAW_FIELD
    else:
        timestamp_path = _mapped_path(timestamp_source, mapping)
    return PipelineLayout(
        parser_kind="dissect",
        source_paths=source_paths,
        timestamp_source_path=timestamp_path,
        cleanup_fields=tuple(mapping.values()),
        pattern=rewritten,
    )


def _rewrite_dissect_pattern(pattern: str) -> tuple[str, dict[str, str]]:
    mapping: dict[str, str] = {}
    counter = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal counter
        token = match.group(1)
        if token == "":
            return "%{}"
        modifier = ""
        name = token
        if name.startswith("+"):
            modifier = "+"
            name = name[1:]
        elif name.endswith("->"):
            modifier = "->"
            name = name[:-2]
        if not name:
            return "%{}"
        if name not in mapping:
            mapping[name] = f"b2d{counter}"
            counter += 1
        return f"%{{{modifier}{mapping[name]}}}"

    return re.sub(r"%\{([^{}]*)\}", replace, pattern), mapping


def _build_grok_layout(
    schema: SchemaSpec,
    parser: GrokParser,
) -> PipelineLayout:
    rewritten, mapping = _rewrite_grok_pattern(parser.pattern)
    source_paths = _mapped_source_paths(schema, mapping)
    timestamp_source = schema.timestamp.source
    if timestamp_source == "$raw":
        timestamp_path = TEMP_RAW_FIELD
    else:
        timestamp_path = _mapped_path(timestamp_source, mapping)
    return PipelineLayout(
        parser_kind="grok",
        source_paths=source_paths,
        timestamp_source_path=timestamp_path,
        cleanup_fields=tuple(mapping.values()),
        pattern=rewritten,
    )


def _rewrite_grok_pattern(pattern: str) -> tuple[str, dict[str, str]]:
    mapping: dict[str, str] = {}
    counter = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal counter
        token = match.group(1)
        parts = token.split(":")
        if len(parts) < 2 or not parts[1]:
            return match.group(0)
        semantic = parts[1]
        if semantic not in mapping:
            mapping[semantic] = f"b2g{counter}"
            counter += 1
        return f"%{{{parts[0]}:{mapping[semantic]}}}"

    rewritten = re.sub(r"%\{([^{}]+)\}", replace, pattern)
    return f"^(?:{rewritten})$", mapping


def _build_regex_layout(
    schema: SchemaSpec,
    parser: RegexParser,
) -> PipelineLayout:
    rewritten, mapping = _rewrite_regex_pattern(parser.pattern)
    source_paths = _mapped_source_paths(schema, mapping)
    timestamp_source = schema.timestamp.source
    if timestamp_source == "$raw":
        timestamp_path = TEMP_RAW_FIELD
    else:
        timestamp_path = _mapped_path(timestamp_source, mapping)
    return PipelineLayout(
        parser_kind="regex",
        source_paths=source_paths,
        timestamp_source_path=timestamp_path,
        cleanup_fields=tuple(mapping.values()),
        pattern=rewritten,
    )


_NAMED_GROUP_RE = re.compile(
    r"\(\?(?:P<|<)([A-Za-z_][A-Za-z0-9_]*)>"
)


def _rewrite_regex_pattern(pattern: str) -> tuple[str, dict[str, str]]:
    if re.search(r"\\[1-9]", pattern):
        raise PipelineCompileError(
            "numeric backreferences are not supported in regex parsers"
        )
    if "\\k<" in pattern or "(?P=" in pattern:
        raise PipelineCompileError(
            "named backreferences are not supported in regex parsers"
        )
    mapping: dict[str, str] = {}
    counter = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal counter
        name = match.group(1)
        if name not in mapping:
            mapping[name] = f"b2r{counter}"
            counter += 1
        return f"(?<{mapping[name]}>"

    rewritten = _NAMED_GROUP_RE.sub(replace, pattern)
    return f"^(?:{rewritten})$", mapping


def _mapped_source_paths(
    schema: SchemaSpec,
    mapping: dict[str, str],
) -> dict[str, str]:
    source_paths: dict[str, str] = {"$raw": TEMP_RAW_FIELD}
    for field in schema.fields:
        if field.source is None or field.source == "$raw":
            continue
        source_paths[field.source] = _mapped_path(field.source, mapping)
    return source_paths


def _mapped_path(source: str, mapping: dict[str, str]) -> str:
    try:
        return mapping[source]
    except KeyError as error:
        raise PipelineCompileError(
            f"parser has no capture named {source!r}"
        ) from error


def _parser_processors(
    schema: SchemaSpec,
    layout: PipelineLayout,
) -> list[dict[str, Any]]:
    parser = schema.parser
    if isinstance(parser, CsvParser):
        if layout.pattern is None or layout.pattern_definitions is None:
            raise PipelineCompileError("CSV layout is missing its grok pattern")
        processors: list[dict[str, Any]] = [
            {
                "grok": {
                    "field": "message",
                    "pattern": layout.pattern,
                    "pattern_definitions": layout.pattern_definitions,
                }
            }
        ]
        quote = _regex_literal(parser.quotechar)
        for capture in layout.cleanup_fields:
            processors.append(
                {
                    "gsub": {
                        "field": capture,
                        "pattern": rf"^{quote}|{quote}$",
                        "replacement": "",
                        "ignore_missing": True,
                    }
                }
            )
            processors.append(
                {
                    "gsub": {
                        "field": capture,
                        "pattern": f"{quote}{quote}",
                        "replacement": parser.quotechar,
                        "ignore_missing": True,
                    }
                }
            )
        return processors

    if isinstance(parser, JsonParser):
        return [
            {
                "json": {
                    "field": "message",
                    "target_field": TEMP_OBJECT_FIELD,
                }
            }
        ]

    if isinstance(parser, KvParser):
        return [
            {
                "kv": {
                    "field": "message",
                    "target_field": TEMP_OBJECT_FIELD,
                    "field_split": parser.field_split,
                    "value_split": parser.value_split,
                    "trim_value": '"',
                }
            }
        ]

    if isinstance(parser, DissectParser):
        if layout.pattern is None:
            raise PipelineCompileError("dissect layout is missing its pattern")
        return [
            {
                "dissect": {
                    "field": "message",
                    "pattern": layout.pattern,
                }
            }
        ]

    if isinstance(parser, (GrokParser, RegexParser)):
        if layout.pattern is None:
            raise PipelineCompileError("grok layout is missing its pattern")
        config: dict[str, Any] = {
            "field": "message",
            "pattern": layout.pattern,
        }
        if layout.pattern_definitions:
            config["pattern_definitions"] = layout.pattern_definitions
        return [{"grok": config}]

    raise PipelineCompileError(f"unsupported parser: {parser!r}")


def _timestamp_processors(
    schema: SchemaSpec,
    layout: PipelineLayout,
) -> list[dict[str, Any]]:
    timestamp = schema.timestamp
    source_path = layout.timestamp_source_path
    if timestamp.formats == ["auditd"]:
        processors: list[dict[str, Any]] = [
            {
                "grok": {
                    "field": source_path,
                    "pattern": (
                        r"^audit\(%{BASE10NUM:b2ts0}:"
                        r"%{BASE10NUM:b2ts1}\):$"
                    ),
                }
            }
        ]
        date_config: dict[str, Any] = {
            "field": "b2ts0",
            "target_field": "@timestamp",
            "formats": ["UNIX"],
        }
        if timestamp.timezone is not None:
            date_config["timezone"] = timestamp.timezone
        processors.append({"date": date_config})
        return processors

    date_config = {
        "field": source_path,
        "target_field": "@timestamp",
        "formats": list(timestamp.formats),
    }
    if timestamp.timezone is not None:
        date_config["timezone"] = timestamp.timezone
    return [{"date": date_config}]


def _field_processors(
    schema: SchemaSpec,
    layout: PipelineLayout,
) -> list[dict[str, Any]]:
    processors: list[dict[str, Any]] = []
    for field in schema.fields:
        if field.target == "event.original":
            continue
        if field.target == "event.dataset" and field.constant is not None:
            continue

        if field.constant is not None:
            processors.append(
                {
                    "set": {
                        "field": field.target,
                        "value": field.constant,
                        "override": True,
                    }
                }
            )
        else:
            try:
                source_path = layout.source_paths[field.source or ""]
            except KeyError as error:
                raise PipelineCompileError(
                    f"no source path for field {field.target!r}"
                ) from error
            config: dict[str, Any] = {
                "field": field.target,
                "copy_from": source_path,
                "override": True,
            }
            processor: dict[str, Any] = {"set": config}
            if not field.required and field.target not in REQUIRED_FIELDS:
                processor["ignore_failure"] = True
            processors.append(processor)

        processors.extend(_field_type_processors(field))
    return processors


def _field_type_processors(field: FieldSpec) -> list[dict[str, Any]]:
    if field.type in (FieldType.STRING, FieldType.ARRAY):
        return []
    if field.type is FieldType.DATETIME:
        if field.format == "auditd":
            raise PipelineCompileError(
                "auditd datetime fields other than @timestamp are not "
                "supported"
            )
        config: dict[str, Any] = {
            "field": field.target,
            "target_field": field.target,
            "formats": [field.format or "ISO8601"],
        }
        if field.timezone is not None:
            config["timezone"] = field.timezone
        return [{"date": config}]

    convert_type = {
        FieldType.INTEGER: "integer",
        FieldType.FLOAT: "float",
        FieldType.BOOLEAN: "boolean",
        FieldType.IP: "ip",
    }[field.type]
    return [
        {
            "convert": {
                "field": field.target,
                "type": convert_type,
                "ignore_missing": True,
            }
        }
    ]


def _cleanup_processors(layout: PipelineLayout) -> list[dict[str, Any]]:
    fields: list[str] = []
    for name in (
        *layout.cleanup_fields,
        "b2ts0",
        "b2ts1",
        TEMP_RAW_FIELD,
    ):
        if name not in fields:
            fields.append(name)
    return [
        {
            "remove": {
                "field": name,
                "ignore_missing": True,
            }
        }
        for name in fields
    ]



