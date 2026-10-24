"""Validate compiled B2 pipelines against bounded representative samples.

The default mode is a deterministic offline simulation of the generated
processors. It is deliberately narrower than Elasticsearch: it supports the
processors and options emitted by :mod:`compile_es` plus a few simple
allowlisted processors. When a live Elasticsearch client is supplied,
``mode="es_simulate"`` uses the real ``_simulate`` API instead.

Acceptance follows ``group_B/CONTRACTS.md``:

* at least five records, or every available record when fewer than five exist;
* every non-failure record has the four required fields;
* every non-failure ``@timestamp`` is UTC ISO 8601;
* no type errors for mapped fields;
* parse failures keep the required fields, carry ``_parse_failure`` and
  ``error.message``;
* at least one sample parses successfully.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from group_B.common.errors import SchemaValidationError
from group_B.schema_generation.compile_es import (
    ALLOWED_PROCESSORS,
    FORBIDDEN_PROCESSORS,
    MAX_PATTERN_LENGTH,
    MAX_SAMPLE_LINE_LENGTH,
    PARSE_FAILURE_TAG,
    REQUIRED_FIELDS,
    PipelineSafetyError,
)
from group_B.schema_generation.models import (
    CsvParser,
    FieldSpec,
    FieldType,
    SchemaSpec,
    ValidationReport,
)

MAX_VALIDATION_SAMPLES = 50
MAX_REPORT_ERRORS = 20
_PROCESSOR_NAMES = ALLOWED_PROCESSORS - {"on_failure"}
_COMMON_OPTIONS = frozenset(
    {"description", "if", "ignore_failure", "on_failure", "tag"}
)
_DATE_FORMATS = {"ISO8601", "UNIX", "UNIX_MS", "TAI64N"}
_CONVERT_TYPES = {
    "integer",
    "long",
    "float",
    "double",
    "boolean",
    "ip",
    "string",
    "auto",
}


class _ProcessorFailure(Exception):
    """A deterministic simulator processor failure."""


class _DropDocument(Exception):
    """The simulated pipeline dropped the document."""


def validate_pipeline_safety(pipeline: dict[str, Any]) -> None:
    """Raise ``PipelineSafetyError`` if a pipeline violates the allowlist."""

    if not isinstance(pipeline, dict):
        raise PipelineSafetyError("pipeline must be a dict")
    processors = pipeline.get("processors")
    if not isinstance(processors, list) or not processors:
        raise PipelineSafetyError("pipeline processors must be a non-empty list")
    _validate_processors(processors, "processors")
    on_failure = pipeline.get("on_failure")
    if on_failure is not None:
        if not isinstance(on_failure, list) or not on_failure:
            raise PipelineSafetyError(
                "pipeline on_failure must be a non-empty list"
            )
        _validate_processors(on_failure, "on_failure")


def _validate_processors(processors: list[Any], location: str) -> None:
    for index, processor in enumerate(processors):
        where = f"{location}[{index}]"
        if not isinstance(processor, dict) or not processor:
            raise PipelineSafetyError(f"{where} must be a non-empty object")
        if "if" in processor:
            raise PipelineSafetyError(
                f"{where} uses an if condition; generated pipelines may not "
                "contain executable conditions"
            )
        keys = [
            key
            for key in processor
            if key not in _COMMON_OPTIONS
        ]
        if len(keys) != 1:
            raise PipelineSafetyError(
                f"{where} must contain exactly one processor type"
            )
        processor_type = keys[0]
        if processor_type in FORBIDDEN_PROCESSORS:
            raise PipelineSafetyError(
                f"{where} uses forbidden processor {processor_type!r}"
            )
        if processor_type not in _PROCESSOR_NAMES:
            raise PipelineSafetyError(
                f"{where} uses non-allowlisted processor "
                f"{processor_type!r}"
            )
        config = processor[processor_type]
        if not isinstance(config, dict):
            raise PipelineSafetyError(
                f"{where}.{processor_type} must be an object"
            )
        _validate_processor_config(
            processor_type,
            config,
            f"{where}.{processor_type}",
        )
        nested = processor.get("on_failure")
        if nested is not None:
            if not isinstance(nested, list) or not nested:
                raise PipelineSafetyError(
                    f"{where}.on_failure must be a non-empty list"
                )
            _validate_processors(nested, f"{where}.on_failure")


def _validate_processor_config(
    processor_type: str,
    config: dict[str, Any],
    where: str,
) -> None:
    # Elasticsearch accepts ``if`` inside the processor configuration object.
    # Check both that location and the processor-level location above so a
    # condition cannot bypass the generated-pipeline safety gate.
    if "if" in config:
        raise PipelineSafetyError(
            f"{where} uses an if condition; generated pipelines may not "
            "contain executable conditions"
        )
    if processor_type in {"grok", "dissect", "gsub"}:
        pattern = config.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise PipelineSafetyError(f"{where}.pattern must be a string")
        _validate_pattern_safety(pattern, f"{where}.pattern")
    if processor_type == "grok":
        definitions = config.get("pattern_definitions", {})
        if not isinstance(definitions, dict):
            raise PipelineSafetyError(
                f"{where}.pattern_definitions must be an object"
            )
        for name, definition in definitions.items():
            if not isinstance(name, str) or not isinstance(definition, str):
                raise PipelineSafetyError(
                    f"{where}.pattern_definitions must map strings to strings"
                )
            _validate_pattern_safety(
                definition,
                f"{where}.pattern_definitions[{name!r}]",
            )
    if processor_type == "kv":
        for key in ("field_split", "value_split"):
            value = config.get(key)
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise PipelineSafetyError(
                        f"{where}.{key} must be a non-empty string"
                    )
                _validate_pattern_safety(value, f"{where}.{key}")
    if processor_type == "date":
        formats = config.get("formats")
        if not isinstance(formats, list) or not formats:
            raise PipelineSafetyError(
                f"{where}.formats must be a non-empty list"
            )
        for value in formats:
            if not isinstance(value, str) or not value:
                raise PipelineSafetyError(
                    f"{where}.formats must contain non-empty strings"
                )
        timezone_value = config.get("timezone")
        if timezone_value is not None:
            _validate_timezone(timezone_value, f"{where}.timezone")
    if processor_type == "convert":
        convert_type = config.get("type")
        if convert_type not in _CONVERT_TYPES:
            raise PipelineSafetyError(
                f"{where}.type must be one of {sorted(_CONVERT_TYPES)}"
            )
    if processor_type in {
        "set",
        "remove",
        "rename",
        "append",
        "convert",
        "grok",
        "dissect",
        "json",
        "kv",
        "date",
        "gsub",
        "lowercase",
        "uppercase",
        "trim",
        "split",
        "join",
        "user_agent",
        "uri_parts",
    }:
        field = config.get("field")
        if not isinstance(field, str) or not field:
            raise PipelineSafetyError(f"{where}.field must be a string")
        _validate_pipeline_path(field, f"{where}.field")
    if processor_type == "set":
        copy_from = config.get("copy_from")
        if copy_from is not None:
            if not isinstance(copy_from, str) or not copy_from:
                raise PipelineSafetyError(
                    f"{where}.copy_from must be a string"
                )
            _validate_pipeline_path(copy_from, f"{where}.copy_from")
    if processor_type in {"rename", "json", "kv", "date"}:
        target_field = config.get("target_field")
        if target_field is not None:
            if not isinstance(target_field, str) or not target_field:
                raise PipelineSafetyError(
                    f"{where}.target_field must be a string"
                )
            _validate_pipeline_path(
                target_field,
                f"{where}.target_field",
            )


def _validate_timezone(value: Any, where: str) -> None:
    if not isinstance(value, str) or not value:
        raise PipelineSafetyError(f"{where} must be a timezone string")
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise PipelineSafetyError(f"{where} is not a known timezone") from error


def _validate_pipeline_path(path: str, where: str) -> None:
    if path != "@timestamp" and (
        path.startswith(("_", "@")) or "@" in path
    ):
        raise PipelineSafetyError(f"{where} uses a reserved field: {path!r}")
    if ".." in path or "*" in path or any(
        part == "" for part in path.split(".")
    ):
        raise PipelineSafetyError(f"{where} is not a safe field path: {path!r}")


def _validate_pattern_safety(pattern: str, where: str) -> None:
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PipelineSafetyError(
            f"{where} exceeds the {MAX_PATTERN_LENGTH}-character bound"
        )
    if "\x00" in pattern:
        raise PipelineSafetyError(f"{where} contains a null byte")
    if re.search(r"\\[1-9]", pattern) or "\\k<" in pattern or "(?P=" in pattern:
        raise PipelineSafetyError(
            f"{where} uses backreferences, which are not allowed"
        )
    if _has_nested_quantifier(pattern):
        raise PipelineSafetyError(
            f"{where} contains nested unbounded quantifiers"
        )


def _has_nested_quantifier(pattern: str) -> bool:
    stack: list[bool] = []
    index = 0
    in_class = False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[" and not in_class:
            in_class = True
            index += 1
            continue
        if char == "]" and in_class:
            in_class = False
            index += 1
            continue
        if in_class:
            index += 1
            continue
        if char == "(":
            stack.append(False)
        elif char == ")":
            if not stack:
                index += 1
                continue
            contains_unbounded = stack.pop()
            quantifier = _quantifier_at(pattern, index + 1)
            if quantifier is not None and quantifier[1]:
                if contains_unbounded:
                    return True
                if stack:
                    stack[-1] = True
            elif quantifier is not None and stack:
                # A bounded outer quantifier does not make the parent
                # unbounded, but the group itself is still repeated.
                pass
        elif char in "*+":
            if stack:
                stack[-1] = True
        elif char == "{":
            match = re.match(r"\{(\d+),(\d*)\}", pattern[index:])
            if match:
                if match.group(2) == "" and stack:
                    stack[-1] = True
                index += len(match.group(0)) - 1
        index += 1
    return False


def _quantifier_at(pattern: str, index: int) -> tuple[str, bool] | None:
    if index >= len(pattern):
        return None
    char = pattern[index]
    if char in "*+":
        return char, True
    if char == "?":
        return char, False
    if char == "{":
        match = re.match(r"\{(\d+)(?:,(\d*))?\}", pattern[index:])
        if match:
            return match.group(0), match.group(2) == ""
    return None


def validate_pipeline(
    schema: SchemaSpec,
    pipeline: dict[str, Any],
    samples: Sequence[str],
    *,
    mode: str = "offline",
    es_client: Any | None = None,
    max_samples: int = MAX_VALIDATION_SAMPLES,
) -> ValidationReport:
    """Validate a compiled pipeline against bounded source samples."""

    if mode not in {"offline", "es_simulate"}:
        raise SchemaValidationError(
            "mode must be 'offline' or 'es_simulate'"
        )
    if mode == "es_simulate" and es_client is None:
        raise SchemaValidationError(
            "es_simulate mode requires an Elasticsearch client"
        )
    if not isinstance(max_samples, int) or isinstance(max_samples, bool):
        raise SchemaValidationError("max_samples must be an integer")
    if max_samples < 1:
        raise SchemaValidationError("max_samples must be at least 1")
    validate_pipeline_safety(pipeline)

    lines, available_count, sample_errors = _prepare_samples(
        schema,
        samples,
        max_samples,
    )
    if sample_errors:
        return _rejected_report(
            mode=mode,
            sample_count=len(lines),
            available_count=available_count,
            errors=sample_errors,
        )

    if mode == "offline":
        documents: list[dict[str, Any] | None] = []
        simulate_errors: list[str] = []
        for index, line in enumerate(lines):
            try:
                documents.append(
                    simulate_pipeline(pipeline, {"message": line})
                )
            except Exception as error:  # noqa: BLE001 - report, do not leak
                simulate_errors.append(
                    f"sample {index + 1} simulation failed: {error}"
                )
                documents.append(None)
        simulate_ok = not simulate_errors
    else:
        documents, simulate_ok, simulate_errors = _simulate_with_es(
            pipeline,
            lines,
            es_client,
        )

    return _evaluate_documents(
        schema,
        documents,
        mode=mode,
        available_count=available_count,
        sample_count=len(lines),
        simulate_ok=simulate_ok,
        simulate_errors=simulate_errors,
    )


def sample_hashes(samples: Sequence[str]) -> list[str]:
    """Return lowercase SHA-256 hashes for provenance metadata."""

    if isinstance(samples, (str, bytes)):
        raise TypeError("samples must be a sequence of strings")
    hashes: list[str] = []
    for line in samples:
        if not isinstance(line, str):
            raise TypeError("every sample line must be a string")
        hashes.append(
            hashlib.sha256(line.encode("utf-8")).hexdigest()
        )
    return hashes


def _prepare_samples(
    schema: SchemaSpec,
    samples: Sequence[str],
    max_samples: int,
) -> tuple[list[str], int, list[str]]:
    if isinstance(samples, (str, bytes)):
        raise TypeError("samples must be a sequence of strings")
    lines: list[str] = []
    errors: list[str] = []
    for index, raw_line in enumerate(samples):
        if not isinstance(raw_line, str):
            errors.append(f"sample {index + 1} is not a string")
            continue
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        if len(line) > MAX_SAMPLE_LINE_LENGTH:
            errors.append(
                f"sample {index + 1} exceeds the "
                f"{MAX_SAMPLE_LINE_LENGTH}-character input bound"
            )
            continue
        lines.append(line)

    if isinstance(schema.parser, CsvParser) and schema.parser.has_header:
        if lines:
            lines = lines[1:]

    available_count = len(lines)
    if available_count == 0 and not errors:
        errors.append("no representative samples are available")
    return lines[:max_samples], available_count, errors


def _simulate_with_es(
    pipeline: dict[str, Any],
    lines: list[str],
    es_client: Any,
) -> tuple[list[dict[str, Any] | None], bool, list[str]]:
    docs = [{"_source": {"message": line}} for line in lines]
    try:
        try:
            response = es_client.ingest.simulate(
                pipeline=pipeline,
                docs=docs,
            )
        except TypeError:
            # Older clients accept the request through ``body`` instead of
            # keyword arguments. Keep this fallback inside the outer handler
            # so a failed fallback still becomes a validation error.
            response = es_client.ingest.simulate(
                body={"pipeline": pipeline, "docs": docs}
            )
    except Exception as error:  # noqa: BLE001 - report the request failure
        return [], False, [f"Elasticsearch _simulate failed: {error}"]

    if hasattr(response, "body"):
        response = response.body
    elif hasattr(response, "to_dict"):
        response = response.to_dict()
    else:
        try:
            response = dict(response)
        except (TypeError, ValueError) as error:
            return [], False, [
                f"Elasticsearch _simulate returned an unreadable response: "
                f"{error}"
            ]

    items = response.get("docs")
    if not isinstance(items, list):
        return [], False, [
            "Elasticsearch _simulate response has no docs list"
        ]
    if len(items) != len(lines):
        return [], False, [
            "Elasticsearch _simulate returned a different number of docs"
        ]

    documents: list[dict[str, Any] | None] = []
    errors: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"sample {index + 1} simulate result is not an object")
            documents.append(None)
            continue
        if "error" in item:
            errors.append(
                f"sample {index + 1} _simulate error: {item['error']}"
            )
            documents.append(None)
            continue
        doc = item.get("doc", {})
        source = doc.get("_source") if isinstance(doc, dict) else None
        if not isinstance(source, dict):
            errors.append(
                f"sample {index + 1} _simulate result has no _source"
            )
            documents.append(None)
            continue
        documents.append(source)
    return documents, not errors, errors


def _evaluate_documents(
    schema: SchemaSpec,
    documents: list[dict[str, Any] | None],
    *,
    mode: str,
    available_count: int,
    sample_count: int,
    simulate_ok: bool,
    simulate_errors: list[str],
) -> ValidationReport:
    errors: list[str] = list(simulate_errors)
    non_failure_count = 0
    required_ok_count = 0
    timestamp_ok_count = 0
    type_error_count = 0
    parse_failure_count = 0

    for index, document in enumerate(documents):
        if document is None:
            if not simulate_errors:
                _add_error(errors, f"sample {index + 1} produced no document")
            continue
        is_failure = _is_parse_failure(document)
        if is_failure:
            parse_failure_count += 1
            if not _has_required_fields(document):
                _add_error(
                    errors,
                    f"sample {index + 1} parse failure is missing required "
                    "fields",
                )
            if not _non_empty(
                _get_field(document, "error.message", missing=None)
            ):
                _add_error(
                    errors,
                    f"sample {index + 1} parse failure is missing "
                    "error.message",
                )
        else:
            non_failure_count += 1
            if _has_required_fields(document):
                required_ok_count += 1
            else:
                _add_error(
                    errors,
                    f"sample {index + 1} is missing required fields",
                )
            if _timestamp_ok(document.get("@timestamp")):
                timestamp_ok_count += 1
            else:
                _add_error(
                    errors,
                    f"sample {index + 1} @timestamp is not UTC ISO 8601",
                )

        count, messages = _count_type_errors(schema, document)
        type_error_count += count
        for message in messages:
            _add_error(errors, f"sample {index + 1} {message}")

    if non_failure_count == 0:
        _add_error(errors, "no sample parsed successfully")

    minimum_samples = min(5, available_count)
    if sample_count < minimum_samples:
        _add_error(
            errors,
            "validation needs at least 5 samples, or every available "
            "sample when fewer than 5 exist",
        )

    required_rate = (
        required_ok_count / non_failure_count
        if non_failure_count
        else 1.0
    )
    timestamp_rate = (
        timestamp_ok_count / non_failure_count
        if non_failure_count
        else 1.0
    )
    accepted = (
        not errors
        and simulate_ok
        and non_failure_count > 0
        and required_rate == 1.0
        and timestamp_rate == 1.0
        and type_error_count == 0
        and sample_count >= minimum_samples
    )
    if not accepted and not errors:
        _add_error(errors, "pipeline did not satisfy the acceptance gate")

    return ValidationReport(
        mode=mode,  # type: ignore[arg-type]
        accepted=accepted,
        sample_count=sample_count,
        available_sample_count=available_count,
        required_field_rate=required_rate,
        timestamp_parse_rate=timestamp_rate,
        type_error_count=type_error_count,
        parse_failure_count=parse_failure_count,
        errors=errors,
    )


def _rejected_report(
    *,
    mode: str,
    sample_count: int,
    available_count: int,
    errors: list[str],
) -> ValidationReport:
    return ValidationReport(
        mode=mode,  # type: ignore[arg-type]
        accepted=False,
        sample_count=sample_count,
        available_sample_count=available_count,
        required_field_rate=0.0,
        timestamp_parse_rate=0.0,
        type_error_count=0,
        parse_failure_count=0,
        errors=errors or ["validation failed"],
    )


def _add_error(errors: list[str], message: str) -> None:
    if len(errors) < MAX_REPORT_ERRORS:
        errors.append(message)
    elif len(errors) == MAX_REPORT_ERRORS:
        errors.append("additional validation errors omitted")


_MISSING = object()


def _is_parse_failure(document: dict[str, Any]) -> bool:
    tags = document.get("tags")
    if isinstance(tags, list):
        return PARSE_FAILURE_TAG in tags
    return tags == PARSE_FAILURE_TAG


def _has_required_fields(document: dict[str, Any]) -> bool:
    return all(
        _non_empty(_get_field(document, field, missing=None))
        for field in REQUIRED_FIELDS
    )


def _non_empty(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def _timestamp_ok(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        _parse_datetime(value, ["ISO8601"], None)
    except (TypeError, ValueError):
        return False
    return True


def _count_type_errors(
    schema: SchemaSpec,
    document: dict[str, Any],
) -> tuple[int, list[str]]:
    count = 0
    messages: list[str] = []
    for field in schema.fields:
        value = _get_field(document, field.target, missing=_MISSING)
        if value is _MISSING or value is None:
            continue
        if _value_matches_type(value, field):
            continue
        count += 1
        messages.append(
            f"field {field.target!r} does not match type "
            f"{field.type.value!r}"
        )
    return count, messages


def _value_matches_type(value: Any, field: FieldSpec) -> bool:
    field_type = field.type
    if field_type is FieldType.STRING:
        return isinstance(value, str)
    if field_type is FieldType.INTEGER:
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type is FieldType.FLOAT:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )
    if field_type is FieldType.BOOLEAN:
        return isinstance(value, bool)
    if field_type is FieldType.ARRAY:
        return isinstance(value, list)
    if field_type is FieldType.IP:
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True
    if field_type is FieldType.DATETIME:
        if not isinstance(value, str):
            return False
        try:
            _parse_datetime(
                value,
                [field.format or "ISO8601"],
                field.timezone,
            )
        except (TypeError, ValueError):
            return False
        return True
    return False


def simulate_pipeline(
    pipeline: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any] | None:
    """Run a pipeline through the deterministic offline reference simulator."""

    validate_pipeline_safety(pipeline)
    if not isinstance(source, dict):
        raise SchemaValidationError("source must be a dict")
    document = copy.deepcopy(source)
    metadata: dict[str, Any] = {
        "_ingest": {
            "timestamp": _utc_now_iso(),
            "on_failure_message": "",
        }
    }
    try:
        _run_processors(
            pipeline.get("processors", []),
            document,
            metadata,
        )
    except _DropDocument:
        return None
    except _ProcessorFailure as error:
        on_failure = pipeline.get("on_failure")
        if not isinstance(on_failure, list) or not on_failure:
            raise
        metadata["_ingest"]["on_failure_message"] = str(error)
        _run_processors(on_failure, document, metadata, in_failure=True)
    return document


def _run_processors(
    processors: list[Any],
    document: dict[str, Any],
    metadata: dict[str, Any],
    *,
    in_failure: bool = False,
) -> None:
    for processor in processors:
        if not isinstance(processor, dict):
            raise _ProcessorFailure("processor is not an object")
        processor_type, config = _split_processor(processor)
        try:
            _run_processor(
                processor_type,
                config,
                document,
                metadata,
            )
        except _DropDocument:
            raise
        except Exception as error:  # noqa: BLE001 - simulator boundary
            if processor.get("ignore_failure"):
                continue
            nested = processor.get("on_failure")
            if isinstance(nested, list) and nested:
                metadata["_ingest"]["on_failure_message"] = str(error)
                _run_processors(
                    nested,
                    document,
                    metadata,
                    in_failure=True,
                )
                continue
            prefix = "on_failure " if in_failure else ""
            raise _ProcessorFailure(
                f"{prefix}{processor_type}: {error}"
            ) from error


def _split_processor(
    processor: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    keys = [key for key in processor if key in _PROCESSOR_NAMES]
    if len(keys) != 1:
        raise _ProcessorFailure(
            "processor must contain exactly one supported type"
        )
    config = processor[keys[0]]
    if not isinstance(config, dict):
        raise _ProcessorFailure(
            f"{keys[0]} processor configuration must be an object"
        )
    return keys[0], config


def _run_processor(
    processor_type: str,
    config: dict[str, Any],
    document: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    if processor_type == "set":
        _run_set(config, document, metadata)
        return
    if processor_type == "remove":
        field = _required_field(config)
        removed = _remove_field(document, field)
        if not removed and not config.get("ignore_missing", False):
            raise _ProcessorFailure(f"field {field!r} does not exist")
        return
    if processor_type == "rename":
        field = _required_field(config)
        target = config.get("target_field")
        if not isinstance(target, str) or not target:
            raise _ProcessorFailure("rename target_field is required")
        value = _get_field(document, field, missing=_MISSING)
        if value is _MISSING:
            if config.get("ignore_missing", False):
                return
            raise _ProcessorFailure(f"field {field!r} does not exist")
        _set_field(document, target, value)
        _remove_field(document, field)
        return
    if processor_type == "grok":
        field = _required_field(config)
        value = _string_field(document, field)
        pattern = config.get("pattern")
        definitions = config.get("pattern_definitions", {})
        if not isinstance(pattern, str):
            raise _ProcessorFailure("grok pattern is required")
        regex = _grok_regex(pattern, definitions)
        match = re.search(regex, value)
        if match is None:
            raise _ProcessorFailure(f"grok pattern did not match {field!r}")
        for name, captured in match.groupdict().items():
            if captured is not None:
                _set_field(document, name, captured)
        return
    if processor_type == "dissect":
        field = _required_field(config)
        value = _string_field(document, field)
        pattern = config.get("pattern")
        if not isinstance(pattern, str):
            raise _ProcessorFailure("dissect pattern is required")
        for name, captured in _dissect_values(pattern, value).items():
            _set_field(document, name, captured)
        return
    if processor_type == "json":
        field = _required_field(config)
        value = _string_field(document, field)
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise _ProcessorFailure(f"json parse failed: {error}") from error
        target = config.get("target_field", field)
        _set_field(document, target, parsed)
        return
    if processor_type == "kv":
        field = _required_field(config)
        value = _string_field(document, field)
        parsed = _parse_kv(value, config)
        target = config.get("target_field")
        if isinstance(target, str) and target:
            _set_field(document, target, parsed)
        else:
            document.update(parsed)
        return
    if processor_type == "date":
        field = _required_field(config)
        value = _get_field(document, field, missing=_MISSING)
        if value is _MISSING:
            if config.get("ignore_missing", False):
                return
            raise _ProcessorFailure(f"field {field!r} does not exist")
        formats = config.get("formats")
        if not isinstance(formats, list) or not formats:
            raise _ProcessorFailure("date formats are required")
        parsed = _parse_datetime(
            value,
            [str(item) for item in formats],
            config.get("timezone"),
        )
        target = config.get("target_field", field)
        _set_field(document, target, _format_datetime(parsed))
        return
    if processor_type == "convert":
        field = _required_field(config)
        value = _get_field(document, field, missing=_MISSING)
        if value is _MISSING:
            if config.get("ignore_missing", False):
                return
            raise _ProcessorFailure(f"field {field!r} does not exist")
        convert_type = config.get("type")
        _set_field(document, field, _convert_value(value, convert_type))
        return
    if processor_type == "gsub":
        field = _required_field(config)
        value = _get_field(document, field, missing=_MISSING)
        if value is _MISSING:
            if config.get("ignore_missing", False):
                return
            raise _ProcessorFailure(f"field {field!r} does not exist")
        if not isinstance(value, str):
            raise _ProcessorFailure("gsub field is not a string")
        pattern = config.get("pattern")
        replacement = config.get("replacement", "")
        if not isinstance(pattern, str) or not isinstance(replacement, str):
            raise _ProcessorFailure("gsub pattern and replacement are required")
        _set_field(document, field, re.sub(pattern, replacement, value))
        return
    if processor_type in {"lowercase", "uppercase", "trim"}:
        field = _required_field(config)
        value = _string_field(document, field)
        if processor_type == "lowercase":
            _set_field(document, field, value.lower())
        elif processor_type == "uppercase":
            _set_field(document, field, value.upper())
        else:
            _set_field(document, field, value.strip())
        return
    if processor_type == "split":
        field = _required_field(config)
        value = _string_field(document, field)
        separator = config.get("separator", ",")
        if not isinstance(separator, str):
            raise _ProcessorFailure("split separator must be a string")
        _set_field(document, field, value.split(separator))
        return
    if processor_type == "join":
        field = _required_field(config)
        value = _get_field(document, field, missing=_MISSING)
        if value is _MISSING:
            raise _ProcessorFailure(f"field {field!r} does not exist")
        if not isinstance(value, list):
            raise _ProcessorFailure("join field is not an array")
        separator = config.get("separator", ",")
        if not isinstance(separator, str):
            raise _ProcessorFailure("join separator must be a string")
        _set_field(document, field, separator.join(str(item) for item in value))
        return
    if processor_type == "append":
        field = _required_field(config)
        value = _render_template(config.get("value"), document, metadata)
        current = _get_field(document, field, missing=_MISSING)
        if current is _MISSING:
            _set_field(document, field, [value])
            return
        if not isinstance(current, list):
            raise _ProcessorFailure("append field is not an array")
        if value not in current or config.get("allow_duplicates", True):
            _set_field(document, field, [*current, value])
        return
    if processor_type == "drop":
        raise _DropDocument()
    if processor_type == "fail":
        raise _ProcessorFailure(
            str(config.get("message", "fail processor"))
        )
    if processor_type in {"user_agent", "uri_parts"}:
        raise _ProcessorFailure(
            f"{processor_type} is not supported by the offline simulator"
        )
    raise _ProcessorFailure(f"unsupported processor {processor_type!r}")


def _run_set(
    config: dict[str, Any],
    document: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    field = _required_field(config)
    if "copy_from" in config:
        copy_from = config["copy_from"]
        if not isinstance(copy_from, str) or not copy_from:
            raise _ProcessorFailure("set copy_from must be a string")
        value = _get_field(document, copy_from, missing=_MISSING)
        if value is _MISSING:
            raise _ProcessorFailure(
                f"copy_from field {copy_from!r} does not exist"
            )
    elif "value" in config:
        value = _render_template(config["value"], document, metadata)
    else:
        raise _ProcessorFailure("set requires value or copy_from")
    if config.get("ignore_empty_value") and value in (None, ""):
        return
    if not config.get("override", True) and _has_field(document, field):
        return
    _set_field(document, field, value)


def _required_field(config: dict[str, Any]) -> str:
    field = config.get("field")
    if not isinstance(field, str) or not field:
        raise _ProcessorFailure("field is required")
    return field


def _string_field(document: dict[str, Any], field: str) -> str:
    value = _get_field(document, field, missing=_MISSING)
    if value is _MISSING:
        raise _ProcessorFailure(f"field {field!r} does not exist")
    if not isinstance(value, str):
        raise _ProcessorFailure(f"field {field!r} is not a string")
    return value


def _get_field(
    document: dict[str, Any],
    path: str,
    *,
    metadata: dict[str, Any] | None = None,
    missing: Any = _MISSING,
) -> Any:
    if path.startswith("_ingest."):
        if metadata is None:
            return missing
        return _walk(metadata, path.split("."), missing)
    return _walk(document, path.split("."), missing)


def _walk(container: Any, parts: list[str], missing: Any) -> Any:
    current = container
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return missing
            current = current[part]
            continue
        if isinstance(current, list):
            if not part.isdigit():
                return missing
            index = int(part)
            if index < 0 or index >= len(current):
                return missing
            current = current[index]
            continue
        return missing
    return current


def _set_field(document: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    current: dict[str, Any] = document
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = value


def _has_field(document: dict[str, Any], path: str) -> bool:
    return _get_field(document, path, missing=_MISSING) is not _MISSING


def _remove_field(document: dict[str, Any], path: str) -> bool:
    parts = path.split(".")
    current: Any = document
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    if not isinstance(current, dict) or parts[-1] not in current:
        return False
    del current[parts[-1]]
    return True


def _render_template(
    value: Any,
    document: dict[str, Any],
    metadata: dict[str, Any],
) -> Any:
    if not isinstance(value, str):
        return value

    def replace(match: re.Match[str]) -> str:
        path = match.group(1).strip()
        found = _get_field(
            document,
            path,
            metadata=metadata,
            missing="",
        )
        if found is _MISSING:
            return ""
        if isinstance(found, (dict, list)):
            return json.dumps(found, ensure_ascii=False)
        return str(found)

    return re.sub(r"\{\{\{\s*([^{}]+?)\s*\}\}\}", replace, value)


def _format_datetime(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _utc_now_iso() -> str:
    return _format_datetime(datetime.now(timezone.utc))


_BUILTIN_GROK: dict[str, str] = {
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "WORD": r"\b\w+\b",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s*",
    "QS": r'"(?:\\.|[^"])*"',
    "INT": r"[+-]?[0-9]+",
    "NUMBER": r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)",
    "BASE10NUM": r"[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)",
    "IP": r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
    "IPORHOST": (
        r"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|"
        r"[A-Za-z0-9][A-Za-z0-9.-]*)"
    ),
    "HOSTNAME": r"[A-Za-z0-9][A-Za-z0-9.-]*",
    "USER": r"[A-Za-z0-9._-]+",
    "USERNAME": r"[A-Za-z0-9._-]+",
    "UUID": (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    ),
    "TIMESTAMP_ISO8601": (
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:"
        r"[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?"
    ),
    "LOGLEVEL": r"(?:TRACE|DEBUG|INFO|WARN|ERROR|FATAL)",
    "URIPATH": r"(?:/[^\s?#]*)?",
    "URIPARAM": r"\?[^\s]*",
    "URIPATHPARAM": r"(?:/[^\s?#]*)?(?:\?[^\s]*)?",
    "URI": r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]+",
}


def _grok_regex(
    pattern: str,
    definitions: dict[str, Any] | None = None,
) -> str:
    merged = dict(_BUILTIN_GROK)
    if definitions:
        for name, value in definitions.items():
            if isinstance(name, str) and isinstance(value, str):
                merged[name] = value

    def expand(text: str, depth: int) -> str:
        if depth > 20:
            raise _ProcessorFailure("grok pattern expansion is too deep")

        def replace(match: re.Match[str]) -> str:
            token = match.group(1)
            parts = token.split(":")
            name = parts[0]
            semantic = parts[1] if len(parts) > 1 and parts[1] else None
            definition = merged.get(name)
            if definition is None:
                raise _ProcessorFailure(
                    f"unknown grok pattern {name!r}"
                )
            expanded = expand(definition, depth + 1)
            if semantic:
                return f"(?P<{semantic}>{expanded})"
            return f"(?:{expanded})"

        return re.sub(r"%\{([^{}]+)\}", replace, text)

    if "%{" in pattern:
        result = expand(pattern, 0)
    else:
        result = pattern
    return re.sub(
        r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>",
        r"(?P<\1>",
        result,
    )


def _dissect_values(pattern: str, text: str) -> dict[str, str]:
    segments: list[tuple[str, str]] = []
    last = 0
    for match in re.finditer(r"%\{([^{}]*)\}", pattern):
        segments.append(("literal", pattern[last:match.start()]))
        segments.append(("token", match.group(1)))
        last = match.end()
    segments.append(("literal", pattern[last:]))

    values: dict[str, str] = {}
    position = 0
    for index, (kind, value) in enumerate(segments):
        if kind == "literal":
            if value:
                if not text.startswith(value, position):
                    raise _ProcessorFailure("dissect literal did not match")
                position += len(value)
            continue

        token = value
        modifier = ""
        name = token
        if name.startswith("+"):
            modifier = "+"
            name = name[1:]
        elif name.endswith("->"):
            modifier = "->"
            name = name[:-2]

        next_literal = _next_dissect_literal(segments, index)
        if next_literal:
            delimiter_index = text.find(next_literal, position)
            if delimiter_index < 0:
                raise _ProcessorFailure("dissect delimiter did not match")
            raw = text[position:delimiter_index]
            position = delimiter_index
        else:
            raw = text[position:]
            position = len(text)

        if not name:
            continue
        if modifier == "+":
            values[name] = values.get(name, "") + raw
        else:
            values[name] = raw

    return values


def _next_dissect_literal(
    segments: list[tuple[str, str]],
    index: int,
) -> str:
    for later_index in range(index + 1, len(segments)):
        if segments[later_index][0] == "literal":
            return segments[later_index][1]
    return ""


def _parse_kv(value: str, config: dict[str, Any]) -> dict[str, str]:
    field_split = config.get("field_split", r"\s+")
    value_split = config.get("value_split", "=")
    trim_key = config.get("trim_key", "")
    trim_value = config.get("trim_value", "")
    prefix = config.get("prefix", "")
    include_keys = config.get("include_keys")
    exclude_keys = config.get("exclude_keys")
    if not isinstance(field_split, str) or not field_split:
        raise _ProcessorFailure("kv field_split must be a string")
    if not isinstance(value_split, str) or not value_split:
        raise _ProcessorFailure("kv value_split must be a string")
    if not isinstance(trim_key, str):
        raise _ProcessorFailure("kv trim_key must be a string")
    if not isinstance(trim_value, str):
        raise _ProcessorFailure("kv trim_value must be a string")
    if not isinstance(prefix, str):
        raise _ProcessorFailure("kv prefix must be a string")
    include = set(include_keys) if isinstance(include_keys, list) else None
    exclude = set(exclude_keys) if isinstance(exclude_keys, list) else set()

    parsed: dict[str, str] = {}
    for token in re.split(field_split, value):
        token = token.strip()
        if not token:
            continue
        parts = token.split(value_split, 1)
        if len(parts) != 2:
            continue
        key, item = parts
        key = key.strip()
        item = item.strip()
        if trim_key:
            key = key.strip(trim_key)
        if trim_value:
            item = item.strip(trim_value)
        if not key:
            continue
        if include is not None and key not in include:
            continue
        if key in exclude:
            continue
        parsed[f"{prefix}{key}"] = item
    return parsed


def _parse_datetime(
    value: Any,
    formats: list[str],
    timezone_name: str | None,
) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = None
        for fmt in formats:
            if fmt == "UNIX":
                parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
                break
            if fmt == "UNIX_MS":
                parsed = datetime.fromtimestamp(
                    float(value) / 1000.0,
                    tz=timezone.utc,
                )
                break
        if parsed is None:
            raise ValueError("numeric timestamp has no UNIX format")
    elif isinstance(value, str):
        parsed = _parse_datetime_string(value.strip(), formats)
    else:
        raise ValueError("timestamp is not a string or number")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        if timezone_name is None:
            raise ValueError(
                "timestamp has no offset and no timezone was supplied"
            )
        try:
            zone = ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as error:
            raise ValueError(
                f"unknown timezone {timezone_name!r}"
            ) from error
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(timezone.utc)


def _parse_datetime_string(value: str, formats: list[str]) -> datetime:
    last_error: Exception | None = None
    for fmt in formats:
        try:
            if fmt == "ISO8601":
                return datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            if fmt == "UNIX":
                return datetime.fromtimestamp(
                    float(value),
                    tz=timezone.utc,
                )
            if fmt == "UNIX_MS":
                return datetime.fromtimestamp(
                    float(value) / 1000.0,
                    tz=timezone.utc,
                )
            if fmt == "auditd":
                match = re.search(
                    r"audit\(([0-9]+(?:\.[0-9]+)?):[0-9]+\):",
                    value,
                )
                if match is None:
                    raise ValueError("not an auditd timestamp")
                return datetime.fromtimestamp(
                    float(match.group(1)),
                    tz=timezone.utc,
                )
            if fmt == "TAI64N":
                raise ValueError("TAI64N is not supported offline")
            python_format = _java_to_strptime(fmt)
            return datetime.strptime(value, python_format)
        except (TypeError, ValueError, OverflowError) as error:
            last_error = error
    if last_error is not None:
        raise ValueError(str(last_error))
    raise ValueError("no timestamp formats were supplied")


def _java_to_strptime(value: str) -> str:
    if "%" in value:
        return value
    tokens = {
        "yyyy": "%Y",
        "yy": "%y",
        "MMMM": "%B",
        "MMM": "%b",
        "MM": "%m",
        "dd": "%d",
        "HH": "%H",
        "hh": "%I",
        "mm": "%M",
        "ss": "%S",
        "SSS": "%f",
        "SS": "%f",
        "EEE": "%a",
        "EEEE": "%A",
        "XXX": "%z",
        "XX": "%z",
        "Z": "%z",
        "a": "%p",
    }
    ordered = sorted(tokens, key=len, reverse=True)
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] == "'":
            end = value.find("'", index + 1)
            if end < 0:
                literal = value[index + 1:]
                index = len(value)
            else:
                literal = value[index + 1:end]
                index = end + 1
            result.append(literal.replace("%", "%%"))
            continue
        matched = False
        for token in ordered:
            if value.startswith(token, index):
                result.append(tokens[token])
                index += len(token)
                matched = True
                break
        if matched:
            continue
        result.append(value[index].replace("%", "%%"))
        index += 1
    return "".join(result)


def _convert_value(value: Any, convert_type: Any) -> Any:
    if not isinstance(convert_type, str):
        raise _ProcessorFailure("convert type is required")
    if convert_type in {"integer", "long"}:
        if isinstance(value, bool):
            raise _ProcessorFailure("boolean cannot convert to integer")
        return int(value)
    if convert_type in {"float", "double"}:
        if isinstance(value, bool):
            raise _ProcessorFailure("boolean cannot convert to float")
        return float(value)
    if convert_type == "boolean":
        return _to_bool(value)
    if convert_type == "ip":
        return str(ipaddress.ip_address(str(value)))
    if convert_type == "string":
        return str(value)
    if convert_type == "auto":
        return value
    raise _ProcessorFailure(f"unsupported convert type {convert_type!r}")


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    raise _ProcessorFailure(f"cannot convert {value!r} to boolean")



