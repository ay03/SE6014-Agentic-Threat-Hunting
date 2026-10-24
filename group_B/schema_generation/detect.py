"""Detect whether a source matches a previously validated B2 schema."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from group_B.schema_generation.registry import RegistryEntry, SchemaRegistry
from group_B.schema_generation.signature import SourceSignature, build_signature


class DetectionResult(BaseModel):
    """Structural signature plus the registry hit, when one exists."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signature: SourceSignature
    entry: RegistryEntry | None = None

    @property
    def known(self) -> bool:
        return self.entry is not None

    @property
    def pipeline_id(self) -> str | None:
        if self.entry is None:
            return None
        return self.entry.pipeline_id


class SchemaDetector:
    """Build a source signature and look it up in the schema registry."""

    def __init__(self, registry: SchemaRegistry) -> None:
        self.registry = registry

    def detect(self, lines: Iterable[str]) -> DetectionResult:
        signature = build_signature(lines)
        return DetectionResult(
            signature=signature,
            entry=self.registry.find_by_signature(signature),
        )
