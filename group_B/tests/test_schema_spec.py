"""Tests for the declarative SchemaSpec and its validation gates."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from group_B.schema_generation.models import (
    FieldSpec,
    FieldType,
    Provenance,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)


def test_aws_schema_is_valid(aws_schema: SchemaSpec) -> None:
    assert aws_schema.dataset == "aws.s3"
    assert aws_schema.pipeline_id == "b2-aws-s3-honeybucket-v1"
    assert aws_schema.timestamp.target == "@timestamp"


def test_auditd_schema_is_valid(auditd_schema: SchemaSpec) -> None:
    assert auditd_schema.dataset == "linux.auditd"
    assert auditd_schema.pipeline_id == "b2-linux-auditd-v1"


def test_schema_round_trip(aws_schema: SchemaSpec) -> None:
    restored = SchemaSpec.model_validate(
        aws_schema.model_dump(mode="json")
    )

    assert restored == aws_schema


def test_missing_required_field_is_rejected(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    data["fields"] = [
        field for field in data["fields"]
        if field["target"] != "message"
    ]

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_duplicate_target_is_rejected(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    data["fields"].append(
        {"target": "message", "source": "Event Name"}
    )

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_event_original_must_use_raw(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    for field in data["fields"]:
        if field["target"] == "event.original":
            field["source"] = "Event ID"

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_event_dataset_constant_must_match(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    for field in data["fields"]:
        if field["target"] == "event.dataset":
            field["constant"] = "other.dataset"

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_timestamp_field_must_not_be_in_fields(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    data["fields"].append(
        {
            "target": "@timestamp",
            "source": "Event DateTime",
            "type": "datetime",
        }
    )

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_event_category_must_be_an_array(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    for field in data["fields"]:
        if field["target"] == "event.category":
            field["type"] = "string"

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_invalid_schema_id_is_rejected(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    data["schema_id"] = "../evil"

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_unknown_parser_is_rejected(aws_schema: SchemaSpec) -> None:
    data = aws_schema.model_dump(mode="json")
    data["parser"] = {"kind": "script"}

    with pytest.raises(ValidationError):
        SchemaSpec.model_validate(data)


def test_field_requires_source_or_constant() -> None:
    with pytest.raises(ValidationError):
        FieldSpec(target="message")


def test_field_rejects_both_source_and_constant() -> None:
    with pytest.raises(ValidationError):
        FieldSpec(
            target="message",
            source="Event Name",
            constant="literal",
        )


def test_field_format_is_only_for_datetime() -> None:
    with pytest.raises(ValidationError):
        FieldSpec(
            target="message",
            source="Event Name",
            format="%Y-%m-%d",
        )


def test_event_category_array_constant_is_valid() -> None:
    field = FieldSpec(
        target="event.category",
        constant=["authentication"],
        type=FieldType.ARRAY,
    )

    assert field.constant == ["authentication"]


def test_field_constant_must_be_json() -> None:
    with pytest.raises(ValidationError):
        FieldSpec(target="message", constant=object())


def test_timestamp_formats_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        TimestampSpec(source="Event DateTime", formats=[])


def test_validation_report_accepts_the_gate() -> None:
    report = ValidationReport(
        mode="offline",
        accepted=True,
        sample_count=5,
        required_field_rate=1.0,
        timestamp_parse_rate=1.0,
        type_error_count=0,
    )

    assert report.accepted


def test_validation_report_rejects_too_few_samples() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=True,
            sample_count=4,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
        )


def test_validation_report_accepts_all_available_samples_under_five() -> None:
    report = ValidationReport(
        accepted=True,
        sample_count=3,
        available_sample_count=3,
        required_field_rate=1.0,
        timestamp_parse_rate=1.0,
        type_error_count=0,
    )

    assert report.accepted


def test_validation_report_rejects_partial_under_five_samples() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=True,
            sample_count=2,
            available_sample_count=3,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
        )


def test_validation_report_rejects_zero_samples() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=True,
            sample_count=0,
            available_sample_count=0,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
        )


def test_validation_report_rejects_more_samples_than_available() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=True,
            sample_count=6,
            available_sample_count=5,
            required_field_rate=1.0,
            timestamp_parse_rate=1.0,
            type_error_count=0,
        )


def test_validation_report_rejects_low_required_rate() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=True,
            sample_count=5,
            required_field_rate=0.9,
            timestamp_parse_rate=1.0,
            type_error_count=0,
        )


def test_rejected_validation_requires_errors() -> None:
    with pytest.raises(ValidationError):
        ValidationReport(
            accepted=False,
            sample_count=0,
            required_field_rate=0.0,
            timestamp_parse_rate=0.0,
            type_error_count=1,
            errors=[],
        )


def test_llm_provenance_requires_repeatability_metadata() -> None:
    with pytest.raises(ValidationError):
        Provenance(generator="llm")


def test_provenance_rejects_bad_sample_hash() -> None:
    with pytest.raises(ValidationError):
        Provenance(generator="heuristic", sample_hashes=["not-a-hash"])
