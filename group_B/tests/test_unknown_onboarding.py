"""Batch 1 end-to-end tests for the two OTRF unknown-format fixtures.

B1 is represented by its deterministic fake: both sources are explicit
no-match results. B2 builds structural signatures, registers validated schemas,
and reuses each schema on the next identical source.
"""

from __future__ import annotations

from pathlib import Path

from group_B.common import FakeRecognizer, RecogniseResult
from group_B.schema_generation.detect import SchemaDetector
from group_B.schema_generation.models import (
    Provenance,
    SchemaSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.signature import SourceSignature


def test_otrf_unknown_formats_are_registered_and_reused(
    tmp_path: Path,
    aws_lines: list[str],
    auditd_lines: list[str],
    aws_schema: SchemaSpec,
    auditd_schema: SchemaSpec,
    aws_signature: SourceSignature,
    auditd_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    recognizer = FakeRecognizer(
        RecogniseResult.unknown("not in B1", reason_code="no_match")
    )

    assert recognizer.recognise(aws_lines).matched is False
    assert recognizer.recognise(auditd_lines).matched is False

    registry = SchemaRegistry(tmp_path)
    detector = SchemaDetector(registry)

    assert detector.detect(aws_lines).known is False
    assert detector.detect(auditd_lines).known is False
    assert aws_signature.hash != auditd_signature.hash

    aws_entry = registry.register(
        schema=aws_schema,
        signature=aws_signature,
        pipeline=minimal_pipeline,
        validation=accepted_validation,
        provenance=heuristic_provenance,
    )
    auditd_entry = registry.register(
        schema=auditd_schema,
        signature=auditd_signature,
        pipeline=minimal_pipeline,
        validation=accepted_validation,
        provenance=heuristic_provenance,
    )

    assert detector.detect(aws_lines).entry == aws_entry
    assert detector.detect(auditd_lines).entry == auditd_entry
    assert detector.detect(aws_lines).pipeline_id == aws_entry.pipeline_id
    assert (
        detector.detect(auditd_lines).pipeline_id
        == auditd_entry.pipeline_id
    )
    assert len(registry.list_entries()) == 2
