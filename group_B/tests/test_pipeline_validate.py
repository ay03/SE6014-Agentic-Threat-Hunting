"""Batch 2 tests for offline and Elasticsearch pipeline validation."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from group_B.common.errors import SchemaValidationError
from group_B.schema_generation.compile_es import (
    MAX_SAMPLE_LINE_LENGTH,
    compile_pipeline,
)
from group_B.schema_generation.models import (
    FieldSpec,
    FieldType,
    JsonParser,
    KvParser,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.validate import (
    sample_hashes,
    simulate_pipeline,
    validate_pipeline,
)


def _json_schema(message_source: str = "msg") -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-json",
        dataset="test.data",
        parser=JsonParser(),
        timestamp=TimestampSpec(source="ts", formats=["ISO8601"]),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source=message_source),
            FieldSpec(target="log.level", source="level"),
        ],
    )


def _json_lines(count: int = 5) -> list[str]:
    return [
        json.dumps(
            {
                "ts": "2026-10-23T12:00:00Z",
                "level": "INFO",
                "msg": f"hello {index}",
            }
        )
        for index in range(count)
    ]


def _bad_type_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="test-bad-type",
        dataset="test.data",
        parser=KvParser(),
        timestamp=TimestampSpec(source="msg", formats=["auditd"]),
        fields=[
            FieldSpec(target="event.dataset", constant="test.data"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", constant="event"),
            FieldSpec(
                target="process.pid",
                source="comm",
                type=FieldType.INTEGER,
            ),
        ],
    )


def test_offline_validation_accepts_aws_fixture(
    aws_schema: SchemaSpec,
    aws_lines: list[str],
) -> None:
    pipeline = compile_pipeline(aws_schema, samples=aws_lines)
    report = validate_pipeline(aws_schema, pipeline, aws_lines)

    assert report.accepted
    assert report.mode == "offline"
    assert report.sample_count == 50
    assert report.available_sample_count == len(aws_lines) - 1
    assert report.required_field_rate == 1.0
    assert report.timestamp_parse_rate == 1.0
    assert report.type_error_count == 0
    assert report.parse_failure_count == 0
    assert report.errors == []


def test_offline_validation_accepts_auditd_fixture(
    auditd_schema: SchemaSpec,
    auditd_lines: list[str],
) -> None:
    pipeline = compile_pipeline(auditd_schema)
    report = validate_pipeline(auditd_schema, pipeline, auditd_lines)

    assert report.accepted
    assert report.sample_count == len(auditd_lines)
    assert report.available_sample_count == len(auditd_lines)
    assert report.parse_failure_count == 0
    assert report.errors == []


def test_offline_validation_accepts_all_available_under_five(
    auditd_schema: SchemaSpec,
    auditd_lines: list[str],
) -> None:
    pipeline = compile_pipeline(auditd_schema)
    report = validate_pipeline(auditd_schema, pipeline, auditd_lines[:3])

    assert report.accepted
    assert report.sample_count == 3
    assert report.available_sample_count == 3


def test_offline_validation_rejects_too_few_when_more_available(
    auditd_schema: SchemaSpec,
    auditd_lines: list[str],
) -> None:
    pipeline = compile_pipeline(auditd_schema)
    report = validate_pipeline(
        auditd_schema,
        pipeline,
        auditd_lines[:5],
        max_samples=4,
    )

    assert not report.accepted
    assert any("at least 5" in error for error in report.errors)


def test_offline_validation_rejects_missing_required_source() -> None:
    schema = _json_schema(message_source="missing")
    pipeline = compile_pipeline(schema)
    lines = _json_lines()
    report = validate_pipeline(schema, pipeline, lines)

    assert not report.accepted
    assert report.parse_failure_count == len(lines)
    assert any(
        "no sample parsed successfully" in error for error in report.errors
    )


def test_parse_failure_keeps_required_fields_and_tag() -> None:
    schema = _json_schema(message_source="missing")
    pipeline = compile_pipeline(schema)
    line = _json_lines(1)[0]
    document = simulate_pipeline(pipeline, {"message": line})

    assert document is not None
    assert document["@timestamp"]
    assert document["event"]["dataset"] == "test.data"
    assert document["event"]["original"] == line
    assert document["message"] == "Failed to parse source record"
    assert document["tags"] == ["_parse_failure"]
    assert document["error"]["message"]


def test_offline_validation_counts_type_errors(
    auditd_lines: list[str],
) -> None:
    schema = _bad_type_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(schema, pipeline, auditd_lines[:5])

    assert not report.accepted
    assert report.type_error_count >= 1
    assert any("does not match type" in error for error in report.errors)


def test_es_simulate_mode_uses_client() -> None:
    class FakeIngest:
        def simulate(
            self,
            *,
            pipeline: dict[str, Any],
            docs: list[dict[str, Any]],
        ) -> dict[str, Any]:
            results = []
            for item in docs:
                document = simulate_pipeline(
                    pipeline,
                    item["_source"],
                )
                results.append({"doc": {"_source": document}})
            return {"docs": results}

    class FakeClient:
        ingest = FakeIngest()

    schema = _json_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(
        schema,
        pipeline,
        _json_lines(),
        mode="es_simulate",
        es_client=FakeClient(),
    )

    assert report.accepted
    assert report.mode == "es_simulate"


def test_es_simulate_mode_falls_back_to_body_api() -> None:
    class BodyIngest:
        def simulate(self, **kwargs: Any) -> dict[str, Any]:
            if "body" not in kwargs:
                raise TypeError("unexpected keyword argument 'pipeline'")
            body = kwargs["body"]
            results = []
            for item in body["docs"]:
                document = simulate_pipeline(
                    body["pipeline"],
                    item["_source"],
                )
                results.append({"doc": {"_source": document}})
            return {"docs": results}

    class BodyClient:
        ingest = BodyIngest()

    schema = _json_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(
        schema,
        pipeline,
        _json_lines(),
        mode="es_simulate",
        es_client=BodyClient(),
    )

    assert report.accepted
    assert report.mode == "es_simulate"


def test_es_simulate_mode_reports_failed_body_fallback() -> None:
    class FailingIngest:
        def simulate(self, **kwargs: Any) -> dict[str, Any]:
            raise TypeError("client does not accept this request")

    class FailingClient:
        ingest = FailingIngest()

    schema = _json_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(
        schema,
        pipeline,
        _json_lines(),
        mode="es_simulate",
        es_client=FailingClient(),
    )

    assert not report.accepted
    assert any("_simulate failed" in error for error in report.errors)


def test_es_simulate_mode_reports_client_errors() -> None:
    class ErrorIngest:
        def simulate(
            self,
            *,
            pipeline: dict[str, Any],
            docs: list[dict[str, Any]],
        ) -> dict[str, Any]:
            return {
                "docs": [
                    {"error": {"type": "parse_exception"}}
                    for _ in docs
                ]
            }

    class ErrorClient:
        ingest = ErrorIngest()

    schema = _json_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(
        schema,
        pipeline,
        _json_lines(),
        mode="es_simulate",
        es_client=ErrorClient(),
    )

    assert not report.accepted
    assert any("_simulate error" in error for error in report.errors)


def test_es_simulate_mode_requires_client() -> None:
    schema = _json_schema()
    pipeline = compile_pipeline(schema)

    with pytest.raises(SchemaValidationError):
        validate_pipeline(
            schema,
            pipeline,
            _json_lines(),
            mode="es_simulate",
        )


def test_validation_rejects_oversized_sample() -> None:
    schema = _json_schema()
    pipeline = compile_pipeline(schema)
    report = validate_pipeline(
        schema,
        pipeline,
        ["x" * (MAX_SAMPLE_LINE_LENGTH + 1)],
    )

    assert not report.accepted
    assert any("input bound" in error for error in report.errors)


def test_sample_hashes_are_sha256_values() -> None:
    hashes = sample_hashes(["a", "b"])

    assert len(hashes) == 2
    assert len(set(hashes)) == 2
    assert all(len(value) == 64 for value in hashes)


def test_validation_report_rejects_all_parse_failures() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            mode="offline",
            accepted=True,
            sample_count=5,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
            parse_failure_count=5,
        )


def test_validation_report_rejects_failure_count_above_samples() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            mode="offline",
            accepted=False,
            sample_count=5,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
            parse_failure_count=6,
            errors=["bad count"],
        )
