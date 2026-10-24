"""Batch 2 tests for the Elasticsearch pipeline compiler."""

from __future__ import annotations

import json
from typing import Any

import pytest

from group_B.schema_generation.compile_es import (
    ALLOWED_PROCESSORS,
    FORBIDDEN_PROCESSORS,
    PipelineCompileError,
    PipelineSafetyError,
    compile_pipeline,
)
from group_B.schema_generation.models import (
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
from group_B.schema_generation.validate import validate_pipeline_safety


def _base_fields(message_source: str = "msg") -> list[FieldSpec]:
    return [
        FieldSpec(target="event.dataset", constant="test.data"),
        FieldSpec(target="event.original", source="$raw"),
        FieldSpec(target="message", source=message_source),
        FieldSpec(target="log.level", source="level"),
    ]


def _json_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-json",
        dataset="test.data",
        parser=JsonParser(),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=_base_fields(),
    )


def _dissect_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-dissect",
        dataset="test.data",
        parser=DissectParser(pattern="%{ts} %{level} %{msg}"),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=_base_fields(),
    )


def _grok_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-grok",
        dataset="test.data",
        parser=GrokParser(
            pattern=(
                "%{TIMESTAMP_ISO8601:ts} %{LOGLEVEL:level} "
                "%{GREEDYDATA:msg}"
            )
        ),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=_base_fields(),
    )


def _regex_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-regex",
        dataset="test.data",
        parser=RegexParser(
            pattern=r"^(?P<ts>\S+) (?P<level>\w+) (?P<msg>.*)$"
        ),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=_base_fields(),
    )


def _processor_types(processors: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for processor in processors:
        for key in processor:
            if key in ALLOWED_PROCESSORS and key != "on_failure":
                found.append(key)
        nested = processor.get("on_failure")
        if isinstance(nested, list):
            found.extend(_processor_types(nested))
    return found


def test_compile_aws_csv_uses_only_allowlisted_processors(
    aws_schema: SchemaSpec,
    aws_lines: list[str],
) -> None:
    pipeline = compile_pipeline(aws_schema, samples=aws_lines)

    assert pipeline["description"].startswith("B2 pipeline for")
    assert pipeline["processors"]
    assert pipeline["on_failure"]
    assert set(_processor_types(pipeline["processors"])) <= (
        ALLOWED_PROCESSORS - {"on_failure"}
    )
    assert not (
        set(_processor_types(pipeline["processors"]))
        & FORBIDDEN_PROCESSORS
    )
    assert any("grok" in processor for processor in pipeline["processors"])
    json.dumps(pipeline, allow_nan=False)


def test_compile_csv_requires_samples(aws_schema: SchemaSpec) -> None:
    with pytest.raises(PipelineCompileError):
        compile_pipeline(aws_schema)


def test_compile_auditd_extracts_audit_timestamp(
    auditd_schema: SchemaSpec,
) -> None:
    pipeline = compile_pipeline(auditd_schema)
    processors = pipeline["processors"]

    assert any(
        "grok" in processor
        and "audit\\(" in processor["grok"]["pattern"]
        for processor in processors
    )
    assert any(
        "date" in processor
        and processor["date"]["formats"] == ["UNIX"]
        for processor in processors
    )


def test_compile_json_uses_json_processor() -> None:
    pipeline = compile_pipeline(_json_schema())

    assert any(
        "json" in processor
        and processor["json"]["target_field"] == "b2_tmp"
        for processor in pipeline["processors"]
    )


def test_compile_dissect_rewrites_captures() -> None:
    pipeline = compile_pipeline(_dissect_schema())
    dissect = next(
        processor["dissect"]
        for processor in pipeline["processors"]
        if "dissect" in processor
    )

    assert dissect["pattern"] == "%{b2d0} %{b2d1} %{b2d2}"
    assert "b2d0" not in json.dumps(pipeline["processors"][-1])


def test_compile_grok_rewrites_semantics() -> None:
    pipeline = compile_pipeline(_grok_schema())
    grok = next(
        processor["grok"]
        for processor in pipeline["processors"]
        if "grok" in processor
    )

    assert "b2g0" in grok["pattern"]
    assert "b2g1" in grok["pattern"]
    assert "b2g2" in grok["pattern"]
    assert grok["pattern"].startswith("^(?:")
    assert grok["pattern"].endswith(")$")


def test_compile_regex_rewrites_python_named_groups() -> None:
    pipeline = compile_pipeline(_regex_schema())
    grok = next(
        processor["grok"]
        for processor in pipeline["processors"]
        if "grok" in processor
    )

    assert "(?P<" not in grok["pattern"]
    assert "(?<b2r0>" in grok["pattern"]
    assert "(?<b2r1>" in grok["pattern"]
    assert "(?<b2r2>" in grok["pattern"]


def test_compile_rejects_unsafe_target() -> None:
    schema = SchemaSpec(
        schema_id="test-unsafe",
        dataset="test.data",
        parser=JsonParser(),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source="msg"),
            FieldSpec(target="_ingest", constant="x"),
        ],
    )

    with pytest.raises(PipelineCompileError):
        compile_pipeline(schema)


def test_compile_rejects_nested_quantifier() -> None:
    schema = SchemaSpec(
        schema_id="test-unsafe-regex",
        dataset="test.data",
        parser=RegexParser(
            pattern=r"^(?P<ts>(a+)+) (?P<msg>.*)$"
        ),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source="msg"),
        ],
    )

    with pytest.raises(PipelineSafetyError):
        compile_pipeline(schema)


def test_compile_rejects_constant_type_mismatch() -> None:
    schema = SchemaSpec(
        schema_id="test-constant",
        dataset="test.data",
        parser=JsonParser(),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source="msg"),
            FieldSpec(
                target="process.pid",
                constant="not-an-integer",
                type=FieldType.INTEGER,
            ),
        ],
    )

    with pytest.raises(PipelineCompileError):
        compile_pipeline(schema)


def test_compile_rejects_invalid_timezone() -> None:
    schema = SchemaSpec(
        schema_id="test-timezone",
        dataset="test.data",
        parser=JsonParser(),
        timestamp=TimestampSpec(
            source="ts",
            formats=["ISO8601"],
            timezone="Mars/Olympus",
        ),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source="msg"),
        ],
    )

    with pytest.raises(PipelineCompileError):
        compile_pipeline(schema)


def test_compile_rejects_mixed_auditd_formats() -> None:
    schema = SchemaSpec(
        schema_id="test-auditd",
        dataset="test.data",
        parser=KvParser(),
        timestamp=TimestampSpec(
            source="msg",
            formats=["auditd", "ISO8601"],
        ),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", constant="event"),
        ],
    )

    with pytest.raises(PipelineCompileError):
        compile_pipeline(schema)


def test_safety_rejects_forbidden_processor() -> None:
    with pytest.raises(PipelineSafetyError):
        validate_pipeline_safety(
            {"processors": [{"script": {"source": "ctx.foo = 1"}}]}
        )


def test_safety_rejects_unknown_processor() -> None:
    with pytest.raises(PipelineSafetyError):
        validate_pipeline_safety(
            {"processors": [{"csv": {"field": "message"}}]}
        )


def test_safety_rejects_if_condition() -> None:
    with pytest.raises(PipelineSafetyError):
        validate_pipeline_safety(
            {
                "processors": [
                    {
                        "set": {"field": "message", "value": "x"},
                        "if": "ctx.foo != null",
                    }
                ]
            }
        )


def test_safety_rejects_if_condition_inside_processor_config() -> None:
    with pytest.raises(PipelineSafetyError):
        validate_pipeline_safety(
            {
                "processors": [
                    {
                        "set": {
                            "field": "message",
                            "value": "x",
                            "if": "ctx.foo != null",
                        }
                    }
                ]
            }
        )
