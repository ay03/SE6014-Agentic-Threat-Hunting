"""Tests for the versioned schema registry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from group_B.common.errors import RegistryError
from group_B.schema_generation.models import (
    Provenance,
    SchemaSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import RegistryEntry, SchemaRegistry
from group_B.schema_generation.signature import (
    SourceSignature,
    build_signature,
)


def _register(
    registry: SchemaRegistry,
    *,
    schema: SchemaSpec,
    signature: SourceSignature,
    validation: ValidationReport,
    provenance: Provenance,
    pipeline: dict[str, object],
) -> RegistryEntry:
    return registry.register(
        schema=schema,
        signature=signature,
        pipeline=pipeline,
        validation=validation,
        provenance=provenance,
    )


def test_register_and_lookup(
    tmp_path: Path,
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

    assert entry.schema_spec == aws_schema
    assert entry.pipeline_id == "b2-aws-s3-honeybucket-v1"
    assert registry.find_by_signature(aws_signature) == entry
    assert registry.find_by_signature(aws_signature.hash) == entry
    assert registry.get(aws_schema.schema_id, 1) == entry
    assert registry.latest(aws_schema.schema_id) == entry
    assert registry.list_entries() == [entry]
    assert (
        tmp_path / "schemas" / aws_schema.schema_id / "v1.json"
    ).is_file()
    assert (tmp_path / "index.json").is_file()

    index = json.loads((tmp_path / "index.json").read_text())
    indexed = index["signatures"][aws_signature.hash]
    assert indexed["schema_id"] == aws_schema.schema_id
    assert indexed["pipeline_id"] == entry.pipeline_id


def test_register_is_idempotent(
    tmp_path: Path,
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    first = _register(
        registry,
        schema=aws_schema,
        signature=aws_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )
    second = _register(
        registry,
        schema=aws_schema,
        signature=aws_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )

    assert first == second
    assert len(registry.list_entries()) == 1


def test_versioning_and_latest(
    tmp_path: Path,
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    first = _register(
        registry,
        schema=aws_schema,
        signature=aws_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )

    data = aws_schema.model_dump(mode="json")
    data["version"] = 2
    second_schema = SchemaSpec.model_validate(data)
    second_signature = build_signature(["a,b,c", "1,2,3"])
    second = _register(
        registry,
        schema=second_schema,
        signature=second_signature,
        validation=accepted_validation,
        provenance=heuristic_provenance,
        pipeline=minimal_pipeline,
    )

    assert registry.get(aws_schema.schema_id, 1) == first
    assert registry.latest(aws_schema.schema_id) == second
    assert registry.find_by_signature(second_signature) == second
    assert registry.next_version(aws_schema.schema_id) == 3


def test_duplicate_signature_with_different_schema_is_rejected(
    tmp_path: Path,
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

    data = aws_schema.model_dump(mode="json")
    data["schema_id"] = "other-schema"
    data["dataset"] = "other.dataset"
    for field in data["fields"]:
        if field["target"] == "event.dataset":
            field["constant"] = "other.dataset"
    other_schema = SchemaSpec.model_validate(data)

    with pytest.raises(RegistryError):
        _register(
            registry,
            schema=other_schema,
            signature=aws_signature,
            validation=accepted_validation,
            provenance=heuristic_provenance,
            pipeline=minimal_pipeline,
        )


def test_out_of_order_version_is_rejected(
    tmp_path: Path,
    aws_schema: SchemaSpec,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    data = aws_schema.model_dump(mode="json")
    data["version"] = 2
    schema = SchemaSpec.model_validate(data)

    with pytest.raises(RegistryError):
        _register(
            registry,
            schema=schema,
            signature=build_signature(["a,b,c", "1,2,3"]),
            validation=accepted_validation,
            provenance=heuristic_provenance,
            pipeline=minimal_pipeline,
        )


def test_rejected_validation_is_not_registered(
    tmp_path: Path,
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    heuristic_provenance: Provenance,
    minimal_pipeline: dict[str, object],
) -> None:
    registry = SchemaRegistry(tmp_path)
    rejected = ValidationReport(
        accepted=False,
        sample_count=5,
        required_field_rate=0.5,
        timestamp_parse_rate=0.5,
        type_error_count=2,
        errors=["required fields missing"],
    )

    with pytest.raises(RegistryError):
        _register(
            registry,
            schema=aws_schema,
            signature=aws_signature,
            validation=rejected,
            provenance=heuristic_provenance,
            pipeline=minimal_pipeline,
        )

    assert not (tmp_path / "schemas").exists()


def test_register_requires_a_non_empty_pipeline(
    tmp_path: Path,
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
) -> None:
    registry = SchemaRegistry(tmp_path)

    with pytest.raises(RegistryError):
        _register(
            registry,
            schema=aws_schema,
            signature=aws_signature,
            validation=accepted_validation,
            provenance=heuristic_provenance,
            pipeline={},
        )


def test_index_is_rebuilt_when_missing(
    tmp_path: Path,
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
    (tmp_path / "index.json").unlink()

    assert registry.find_by_signature(aws_signature) == entry
    assert (tmp_path / "index.json").is_file()


def test_tampered_entry_is_rejected(
    tmp_path: Path,
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
    entry_path = registry.entry_path(aws_schema.schema_id, 1)
    entry_path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(RegistryError):
        registry.get(aws_schema.schema_id, 1)


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    registry = SchemaRegistry(tmp_path)

    with pytest.raises(RegistryError):
        registry.get("../evil", 1)


def test_index_path_traversal_is_rejected(
    tmp_path: Path,
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

    index_path = tmp_path / "index.json"
    index = json.loads(index_path.read_text())
    index["signatures"][aws_signature.hash]["path"] = "../../evil.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")

    with pytest.raises(RegistryError):
        registry.find_by_signature(aws_signature)


def test_registry_entry_rejects_pipeline_id_mismatch(
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
) -> None:
    with pytest.raises(ValidationError):
        RegistryEntry(
            schema_spec=aws_schema,
            signature=aws_signature,
            pipeline={"processors": []},
            pipeline_id="wrong-pipeline",
            validation=accepted_validation,
            provenance=heuristic_provenance,
        )


def test_registry_entry_rejects_non_json_pipeline(
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    accepted_validation: ValidationReport,
    heuristic_provenance: Provenance,
) -> None:
    with pytest.raises(ValidationError):
        RegistryEntry(
            schema_spec=aws_schema,
            signature=aws_signature,
            pipeline={"processors": [object()]},
            pipeline_id=aws_schema.pipeline_id,
            validation=accepted_validation,
            provenance=heuristic_provenance,
        )


def test_registry_entry_rejects_rejected_validation(
    aws_schema: SchemaSpec,
    aws_signature: SourceSignature,
    heuristic_provenance: Provenance,
) -> None:
    rejected = ValidationReport(
        accepted=False,
        sample_count=0,
        required_field_rate=0.0,
        timestamp_parse_rate=0.0,
        type_error_count=1,
        errors=["bad"],
    )

    with pytest.raises(ValidationError):
        RegistryEntry(
            schema_spec=aws_schema,
            signature=aws_signature,
            pipeline={"processors": []},
            pipeline_id=aws_schema.pipeline_id,
            validation=rejected,
            provenance=heuristic_provenance,
        )


def test_missing_entries_return_none(tmp_path: Path) -> None:
    registry = SchemaRegistry(tmp_path)

    assert registry.get("missing-schema", 1) is None
    assert registry.latest("missing-schema") is None
    assert registry.list_entries() == []
    assert registry.next_version("missing-schema") == 1
