"""Batch 2 integration test: compile, validate, register, and reuse."""

from __future__ import annotations

from pathlib import Path

from group_B.schema_generation.compile_es import compile_pipeline
from group_B.schema_generation.detect import SchemaDetector
from group_B.schema_generation.models import Provenance, SchemaSpec
from group_B.schema_generation.registry import SchemaRegistry
from group_B.schema_generation.signature import SourceSignature
from group_B.schema_generation.validate import sample_hashes, validate_pipeline


def test_compiled_schema_is_validated_registered_and_reused(
    tmp_path: Path,
    aws_lines: list[str],
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
) -> None:
    pipeline = compile_pipeline(aws_schema, samples=aws_lines)
    report = validate_pipeline(aws_schema, pipeline, aws_lines)
    assert report.accepted

    provenance = Provenance(
        generator="heuristic",
        sample_hashes=sample_hashes(aws_lines[1:6]),
    )
    registry = SchemaRegistry(tmp_path)
    entry = registry.register(
        schema=aws_schema,
        signature=aws_signature,
        pipeline=pipeline,
        validation=report,
        provenance=provenance,
    )

    assert entry.pipeline == pipeline
    assert entry.validation == report
    assert entry.validation.parse_failure_count == 0

    detector = SchemaDetector(registry)
    detection = detector.detect(aws_lines)
    assert detection.known
    assert detection.entry is not None
    assert detection.entry.pipeline_id == aws_schema.pipeline_id
    assert detection.entry.pipeline == pipeline
