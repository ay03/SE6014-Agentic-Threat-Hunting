"""Shared fixtures for Batch 1 schema-generation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from group_B.schema_generation.models import (
    CsvParser,
    FieldSpec,
    FieldType,
    KvParser,
    Provenance,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.signature import SourceSignature, build_signature

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "otrf"
AWS_CSV = FIXTURE_DIR / "AWS_S3_HoneyBucketLogs.csv"
AUDITD = FIXTURE_DIR / "sh_arp_cache_2020-11-10074812.auditd"


def _fixture_lines(path: Path) -> list[str]:
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.fixture
def aws_lines() -> list[str]:
    return _fixture_lines(AWS_CSV)


@pytest.fixture
def auditd_lines() -> list[str]:
    return _fixture_lines(AUDITD)


@pytest.fixture
def aws_signature(aws_lines: list[str]) -> SourceSignature:
    return build_signature(aws_lines)


@pytest.fixture
def auditd_signature(auditd_lines: list[str]) -> SourceSignature:
    return build_signature(auditd_lines)


@pytest.fixture
def aws_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="aws-s3-honeybucket",
        version=1,
        dataset="aws.s3",
        description="AWS S3 honey bucket CSV records",
        parser=CsvParser(delimiter=",", has_header=True),
        timestamp=TimestampSpec(
            source="Event DateTime",
            formats=["ISO8601"],
        ),
        fields=[
            FieldSpec(target="event.dataset", constant="aws.s3"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", source="Event Name"),
            FieldSpec(target="event.action", source="Event Name"),
            FieldSpec(target="event.id", source="Event ID"),
            FieldSpec(
                target="event.category",
                constant=["cloud"],
                type=FieldType.ARRAY,
            ),
            FieldSpec(
                target="source.ip",
                source="Source IP",
                type=FieldType.IP,
            ),
            FieldSpec(
                target="user_agent.original",
                source="Request User Agent",
            ),
            FieldSpec(target="cloud.provider", constant="aws"),
        ],
    )


@pytest.fixture
def auditd_schema() -> SchemaSpec:
    return SchemaSpec(
        schema_id="linux-auditd",
        version=1,
        dataset="linux.auditd",
        description="Linux auditd key-value records",
        parser=KvParser(),
        timestamp=TimestampSpec(source="msg", formats=["auditd"]),
        fields=[
            FieldSpec(target="event.dataset", constant="linux.auditd"),
            FieldSpec(target="event.original", source="$raw"),
            FieldSpec(target="message", constant="Auditd event"),
            FieldSpec(target="event.action", source="type"),
            FieldSpec(
                target="event.category",
                constant=["process"],
                type=FieldType.ARRAY,
            ),
            FieldSpec(target="process.name", source="comm"),
            FieldSpec(target="process.executable", source="exe"),
            FieldSpec(
                target="process.pid",
                source="pid",
                type=FieldType.INTEGER,
            ),
            FieldSpec(target="user.name", source="auid"),
        ],
    )


@pytest.fixture
def accepted_validation() -> ValidationReport:
    return ValidationReport(
        mode="offline",
        accepted=True,
        sample_count=5,
        required_field_rate=1.0,
        timestamp_parse_rate=1.0,
        type_error_count=0,
    )


@pytest.fixture
def heuristic_provenance() -> Provenance:
    return Provenance(generator="heuristic")


@pytest.fixture
def minimal_pipeline() -> dict[str, object]:
    return {
        "description": "Batch 1 test pipeline",
        "processors": [],
    }
