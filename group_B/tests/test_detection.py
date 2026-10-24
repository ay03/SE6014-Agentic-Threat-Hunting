"""Tests for signature-based schema reuse detection."""

from __future__ import annotations

from pathlib import Path

from group_B.schema_generation.detect import SchemaDetector
from group_B.schema_generation.models import (
    Provenance,
    SchemaSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.signature import (
    SignatureKind,
    SourceSignature,
)


def _register(
    registry: SchemaRegistry,
    *,
    schema: SchemaSpec,
    signature: SourceSignature,
    validation: ValidationReport,
    provenance: Provenance,
    pipeline: dict[str, object],
):
    return registry.register(
        schema=schema,
        signature=signature,
        pipeline=pipeline,
        validation=validation,
        provenance=provenance,
    )


def test_unknown_source_is_not_matched(
    tmp_path: Path,
    aws_lines: list[str],
) -> None:
    detector = SchemaDetector(SchemaRegistry(tmp_path))

    result = detector.detect(aws_lines)

    assert result.signature.kind is SignatureKind.CSV
    assert result.known is False
    assert result.entry is None
    assert result.pipeline_id is None


def test_known_source_matches_after_registration(
    tmp_path: Path,
    aws_lines: list[str],
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    entry = _register(
        registry,
        schema=aws_schema,
        signature=aws_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )
    detector = SchemaDetector(registry)

    result = detector.detect(aws_lines)

    assert result.known is True
    assert result.entry == entry
    assert result.pipeline_id == entry.pipeline_id


def test_auditd_does_not_match_an_aws_entry(
    tmp_path: Path,
    auditd_lines: list[str],
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    _register(
        registry,
        schema=aws_schema,
        signature=aws_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )
    detector = SchemaDetector(registry)

    result = detector.detect(auditd_lines)

    assert result.signature.kind is SignatureKind.KV
    assert result.known is False
    assert result.entry is None
