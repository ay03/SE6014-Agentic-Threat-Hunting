"""Batch 0 contract and fixture tests.

These tests intentionally avoid a live LLM or Elasticsearch. They verify the
B1 adapter boundary and the provenance/counts of the OTRF fixtures that later
B2/B3 batches use.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from group_B.common import (
    B1Recognizer,
    FakeRecognizer,
    NullRecognizer,
    RecogniseResult,
    load_b1_recognizer,
)
from group_B.common.errors import (
    GroupBError,
    RecognitionError,
    SchemaValidationError,
)
from group_B.scripts.fetch_otrf_fixtures import DATASETS, SOURCE_COMMIT

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "otrf"
AWS_CSV = FIXTURE_DIR / "AWS_S3_HoneyBucketLogs.csv"
AUDITD = FIXTURE_DIR / "sh_arp_cache_2020-11-10074812.auditd"

EXPECTED_FIXTURE_HASHES = {
    "AWS_S3_HoneyBucketLogs.csv": (
        "193fbd2fd13ae35f32ac9dfe3f79bc42166b734adf63f827addf872c8352229e"
    ),
    "sh_arp_cache_2020-11-10074812.auditd": (
        "6a938e0a94f2f26c153e4c8a37ef0df960b2cb46147407fda00d0344e8f375fc"
    ),
}


def test_matched_result_requires_format_and_dataset() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(matched=True, confidence=0.9)

    result = RecogniseResult(
        matched=True,
        format_id="apache.access",
        dataset="apache.access",
    )

    assert result.pipeline_id is None


def test_matched_result_accepts_pipeline_id() -> None:
    result = RecogniseResult(
        matched=True,
        format_id="apache.access",
        dataset="apache.access",
        pipeline_id="apache-access",
        confidence=0.99,
    )

    assert result.pipeline_id == "apache-access"


def test_matched_result_rejects_reason_code() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(
            matched=True,
            format_id="apache.access",
            dataset="apache.access",
            reason_code="no_match",
        )


def test_matched_confidence_must_be_positive_when_supplied() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(
            matched=True,
            format_id="apache.access",
            dataset="apache.access",
            confidence=0.0,
        )


def test_unknown_result_is_explicit() -> None:
    result = RecogniseResult.unknown("no template")

    assert result.matched is False
    assert result.confidence == 0.0
    assert result.reason_code == "no_match"
    assert result.evidence["reason"] == "no template"


def test_unknown_reason_keyword_does_not_collide() -> None:
    result = RecogniseResult.unknown("default", reason="explicit")

    assert result.evidence["reason"] == "explicit"


def test_whitespace_only_match_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(
            matched=True,
            format_id="   ",
            dataset="apache.access",
        )


def test_unmatched_result_rejects_match_metadata() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(
            matched=False,
            format_id="apache.access",
            dataset="apache.access",
        )


def test_unmatched_result_rejects_positive_confidence() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(matched=False, confidence=0.9)


def test_confidence_is_bounded_and_numeric() -> None:
    with pytest.raises(ValidationError):
        RecogniseResult(matched=False, confidence=1.5)
    with pytest.raises(ValidationError):
        RecogniseResult(matched=False, confidence=-0.1)
    with pytest.raises(ValidationError):
        RecogniseResult(matched=False, confidence="0.5")


def test_extra_keys_are_ignored() -> None:
    result = RecogniseResult(
        matched=False,
        confidence=0.0,
        unknown_key="ignored",
    )

    assert "unknown_key" not in result.model_dump()


def test_b1_adapter_coerces_dict() -> None:
    def recognise(lines: list[str]) -> dict:
        assert lines == ["line-1", "line-2"]
        return {
            "matched": True,
            "format_id": "apache.access",
            "dataset": "apache.access",
            "confidence": 0.98,
            "extra_from_b1": "ignored",
        }

    result = B1Recognizer(recognise).recognise(["line-1", "line-2"])

    assert isinstance(result, RecogniseResult)
    assert result.dataset == "apache.access"
    assert result.pipeline_id is None
    assert result.confidence == 0.98


def test_b1_adapter_accepts_no_match_mapping() -> None:
    result = B1Recognizer(
        lambda lines: {"matched": False, "reason_code": "no_match"}
    ).recognise(["unknown line"])

    assert result.matched is False
    assert result.reason_code == "no_match"
    assert result.format_id is None
    assert result.dataset is None


def test_b1_adapter_passes_through_result() -> None:
    expected = RecogniseResult(
        matched=True,
        format_id="windows.sysmon",
        dataset="windows.sysmon",
        pipeline_id="windows-json",
        confidence=0.9,
    )

    assert B1Recognizer(lambda lines: expected).recognise(["x"]) == expected


def test_b1_adapter_rejects_unknown_return_type() -> None:
    def recognise(lines: list[str]) -> str:
        return "not a result"

    with pytest.raises(RecognitionError):
        B1Recognizer(recognise).recognise(["x"])


def test_b1_adapter_rejects_none() -> None:
    with pytest.raises(RecognitionError):
        B1Recognizer(lambda lines: None).recognise(["x"])


def test_b1_adapter_rejects_single_string() -> None:
    recognizer = B1Recognizer(lambda lines: RecogniseResult.unknown("x"))

    with pytest.raises(TypeError):
        recognizer.recognise("one line")  # type: ignore[arg-type]


def test_null_recognizer_has_configuration_reason_code() -> None:
    result = NullRecognizer().recognise(["x"])

    assert result.matched is False
    assert result.reason_code == "not_configured"
    assert "not configured" in result.evidence["reason"]


def test_fake_recognizer_records_calls() -> None:
    result = RecogniseResult.unknown("test")
    recognizer = FakeRecognizer(result)

    assert recognizer.recognise(["a", "b"]) == result
    assert recognizer.calls == [["a", "b"]]


def test_load_b1_recognizer_requires_module_function_form() -> None:
    with pytest.raises(RecognitionError):
        load_b1_recognizer("not-a-target")


def test_load_b1_recognizer_rejects_disallowed_prefix() -> None:
    with pytest.raises(RecognitionError, match="refusing to import"):
        load_b1_recognizer("subprocess:run")


def test_load_b1_recognizer_success() -> None:
    recognizer = load_b1_recognizer(
        "group_B.tests.b1_fake:recognise",
        allowed_prefixes=("group_B.tests",),
    )

    result = recognizer.recognise(["line"])

    assert result.matched is True
    assert result.dataset == "test.fake"


def test_load_b1_recognizer_missing_attribute() -> None:
    with pytest.raises(RecognitionError, match="has no attribute"):
        load_b1_recognizer(
            "group_B.tests.b1_fake:missing",
            allowed_prefixes=("group_B.tests",),
        )


def test_load_b1_recognizer_missing_module() -> None:
    with pytest.raises(RecognitionError, match="could not import"):
        load_b1_recognizer(
            "group_B.tests.missing_module:recognise",
            allowed_prefixes=("group_B.tests",),
        )


def test_load_b1_recognizer_non_callable_attribute() -> None:
    with pytest.raises(RecognitionError, match="is not callable"):
        load_b1_recognizer(
            "group_B.tests.b1_fake:not_callable",
            allowed_prefixes=("group_B.tests",),
        )


def test_aws_fixture_shape() -> None:
    with AWS_CSV.open(newline="", encoding="utf-8") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        rows = list(reader)

    assert len(header) == 12
    assert len(rows) == 301
    assert all(len(row) == 12 for row in rows)
    assert {
        "Event Type",
        "Event Name",
        "Event DateTime",
        "Source IP",
        "Request User Agent",
    }.issubset(header)


def test_auditd_fixture_shape() -> None:
    lines = [
        line
        for line in AUDITD.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    assert len(lines) == 12
    assert all(line.startswith("type=") for line in lines)
    assert all("msg=audit(" in line for line in lines)


def _read_manifest() -> dict[str, str]:
    manifest = {}
    for line in (FIXTURE_DIR / "SHA256SUMS").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        manifest[name] = digest
    return manifest


def test_fixture_hashes_match_manifest_and_fetch_script() -> None:
    manifest = _read_manifest()
    script_hashes = {
        dataset["output"]: dataset["sha256"] for dataset in DATASETS
    }

    assert set(manifest) == set(EXPECTED_FIXTURE_HASHES)
    assert script_hashes == EXPECTED_FIXTURE_HASHES

    for name, expected in EXPECTED_FIXTURE_HASHES.items():
        actual = hashlib.sha256((FIXTURE_DIR / name).read_bytes()).hexdigest()
        assert actual == expected, name
        assert manifest[name] == expected, name


def test_fixture_provenance_is_pinned() -> None:
    readme = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")

    assert len(SOURCE_COMMIT) == 40
    assert SOURCE_COMMIT in readme
    assert all(SOURCE_COMMIT in dataset["url"] for dataset in DATASETS)


def test_error_payload_has_stable_code() -> None:
    error = SchemaValidationError("bad field", field="source.ip")

    payload = error.to_dict()

    assert payload["ok"] is False
    assert payload["error"]["code"] == "SCHEMA_VALIDATION_FAILED"
    assert payload["error"]["details"] == {"field": "source.ip"}
    assert error.exit_code == 3


def test_base_error_defaults() -> None:
    error = GroupBError("boom")

    assert error.to_dict()["error"]["code"] == "GROUP_B_ERROR"
    assert error.exit_code == 1
