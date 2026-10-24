"""Tests for deterministic source signatures."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from group_B.schema_generation.signature import (
    SignatureKind,
    SourceSignature,
    build_signature,
)


def test_aws_fixture_is_csv(aws_signature: SourceSignature) -> None:
    assert aws_signature.kind is SignatureKind.CSV
    assert aws_signature.shape["delimiter"] == ","
    assert aws_signature.shape["columns"] == 12
    assert aws_signature.shape["has_header"] is True
    assert "event_type" in aws_signature.shape["header"]
    assert len(aws_signature.hash) == 64


def test_auditd_fixture_is_kv(auditd_signature: SourceSignature) -> None:
    assert auditd_signature.kind is SignatureKind.KV
    assert "type" in auditd_signature.shape["common_keys"]
    assert "msg" in auditd_signature.shape["common_keys"]
    assert auditd_signature.shape["min_keys"] >= 2


def test_aws_signature_ignores_values(aws_lines: list[str]) -> None:
    first = build_signature(aws_lines[:10])
    second = build_signature(aws_lines[:20])

    assert first.hash == second.hash
    assert first.sample_count == 10
    assert second.sample_count == 20


def test_aws_and_auditd_signatures_differ(
    aws_signature: SourceSignature,
    auditd_signature: SourceSignature,
) -> None:
    assert aws_signature.hash != auditd_signature.hash


def test_json_signature_ignores_values() -> None:
    first = build_signature(
        ['{"user":"alice","pid":1}', '{"user":"bob","pid":2}']
    )
    second = build_signature(
        ['{"user":"carol","pid":3}', '{"user":"dave","pid":4}']
    )

    assert first.kind is SignatureKind.JSON
    assert first.hash == second.hash
    assert "user:string" in first.shape["paths"]
    assert "pid:integer" in first.shape["paths"]


def test_json_signature_changes_with_structure() -> None:
    first = build_signature(['{"user":"alice","pid":1}'])
    second = build_signature(['{"user":"alice","ppid":1}'])

    assert first.hash != second.hash


def test_empty_signature_is_stable() -> None:
    first = build_signature([])
    second = build_signature(["", "  "])

    assert first.kind is SignatureKind.EMPTY
    assert first.hash == second.hash
    assert first.sample_count == 0


def test_line_signature_fallback() -> None:
    signature = build_signature(["alpha 123", "beta 456"])

    assert signature.kind is SignatureKind.LINE
    assert signature.shape["token_counts"] == [2]
    assert signature.shape["first_tokens"] == ["alpha", "beta"]


def test_blank_lines_do_not_change_signature(aws_lines: list[str]) -> None:
    first = build_signature(aws_lines[:10])
    second = build_signature(aws_lines[:10] + ["", "   "])

    assert first.hash == second.hash
    assert second.sample_count == 10


def test_max_lines_limits_the_sample(aws_lines: list[str]) -> None:
    signature = build_signature(aws_lines, max_lines=5)

    assert signature.sample_count == 5
    assert signature.kind is SignatureKind.CSV


def test_signature_round_trip(aws_signature: SourceSignature) -> None:
    restored = SourceSignature.model_validate(
        aws_signature.model_dump(mode="json")
    )

    assert restored == aws_signature


def test_signature_rejects_tampered_hash() -> None:
    with pytest.raises(ValidationError):
        SourceSignature(
            version=1,
            kind=SignatureKind.LINE,
            shape={},
            sample_count=1,
            hash="0" * 64,
        )


def test_signature_rejects_non_json_shape() -> None:
    with pytest.raises(ValidationError):
        SourceSignature(
            version=1,
            kind=SignatureKind.LINE,
            shape={"bad": object()},
            sample_count=1,
            hash="0" * 64,
        )


def test_build_signature_rejects_a_single_string() -> None:
    with pytest.raises(TypeError):
        build_signature("one line")


def test_build_signature_requires_positive_max_lines() -> None:
    with pytest.raises(ValueError):
        build_signature([], max_lines=0)
