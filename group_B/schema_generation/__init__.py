"""B2 — unknown-schema generation.

Batch 1 provides the declarative schema model, structural signatures, the
versioned registry, and signature-based reuse detection. Batch 2 adds the
Elasticsearch pipeline compiler and validator. Later batches add the
agent-driven generator and CLI.
"""

from group_B.schema_generation.compile_es import (
    ALLOWED_PROCESSORS,
    FORBIDDEN_PROCESSORS,
    PipelineCompileError,
    PipelineLayout,
    PipelineSafetyError,
    build_pipeline_layout,
    compile_pipeline,
)
from group_B.schema_generation.detect import DetectionResult, SchemaDetector
from group_B.schema_generation.models import (
    CsvParser,
    DissectParser,
    FieldSpec,
    FieldType,
    GrokParser,
    JsonParser,
    KvParser,
    Provenance,
    RegexParser,
    SchemaSpec,
    TimestampSpec,
    ValidationReport,
)
from group_B.schema_generation.registry import (
    RegistryEntry,
    RegistryIndex,
    SchemaRegistry,
    SignatureIndexEntry,
    default_registry_root,
)
from group_B.schema_generation.signature import (
    DEFAULT_MAX_SAMPLE_LINES,
    SIGNATURE_VERSION,
    SignatureKind,
    SourceSignature,
    build_signature,
)
from group_B.schema_generation.validate import (
    MAX_VALIDATION_SAMPLES,
    sample_hashes,
    simulate_pipeline,
    validate_pipeline,
    validate_pipeline_safety,
)

__all__ = [
    "ALLOWED_PROCESSORS",
    "CsvParser",
    "DEFAULT_MAX_SAMPLE_LINES",
    "DetectionResult",
    "DissectParser",
    "FORBIDDEN_PROCESSORS",
    "FieldSpec",
    "FieldType",
    "GrokParser",
    "JsonParser",
    "KvParser",
    "MAX_VALIDATION_SAMPLES",
    "PipelineCompileError",
    "PipelineLayout",
    "PipelineSafetyError",
    "Provenance",
    "RegexParser",
    "RegistryEntry",
    "RegistryIndex",
    "SIGNATURE_VERSION",
    "SchemaDetector",
    "SchemaRegistry",
    "SchemaSpec",
    "SignatureIndexEntry",
    "SignatureKind",
    "SourceSignature",
    "TimestampSpec",
    "ValidationReport",
    "build_pipeline_layout",
    "build_signature",
    "compile_pipeline",
    "default_registry_root",
    "sample_hashes",
    "simulate_pipeline",
    "validate_pipeline",
    "validate_pipeline_safety",
]
