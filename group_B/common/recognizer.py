"""Adapter for B1's log-format recogniser.

The shared repository standard names the B1 interface ``recognise(lines)``.
B1's implementation is not in the repository yet, so B2/B3 code depends on
this small protocol instead of importing a concrete module. The adapter
accepts either a ``RecogniseResult`` or a plain dictionary, which keeps the
boundary tolerant while B1 finishes the implementation.

Dynamic import is restricted to a small set of B1 module prefixes. A target
such as ``subprocess:run`` is rejected before import.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Sequence
from typing import Any, Protocol, runtime_checkable

from .errors import RecognitionError
from .models import RecogniseResult

DEFAULT_ALLOWED_PREFIXES: tuple[str, ...] = (
    "group_B.b1",
    "group_B.B1",
    "group_B.recognizer",
    "group_B.b1_recognizer",
)


@runtime_checkable
class Recognizer(Protocol):
    """Interface B3 uses to ask B1 whether a format is known."""

    def recognise(self, lines: Sequence[str]) -> RecogniseResult:
        """Classify representative raw lines."""


def _as_lines(lines: Sequence[str]) -> list[str]:
    if isinstance(lines, (str, bytes)):
        raise TypeError(
            "lines must be a sequence of log lines, not a single string"
        )
    return list(lines)


def _coerce_result(value: Any) -> RecogniseResult:
    if isinstance(value, RecogniseResult):
        return value
    if value is None:
        raise RecognitionError("B1 recogniser returned None")
    if isinstance(value, dict):
        return RecogniseResult.model_validate(value)
    raise RecognitionError(
        "B1 recogniser must return RecogniseResult or dict, got "
        f"{type(value).__name__}"
    )


class B1Recognizer:
    """Wrap B1's ``recognise(lines)`` callable in the Group B protocol."""

    def __init__(
        self,
        recognise: Callable[[Sequence[str]], RecogniseResult | dict[str, Any]],
    ) -> None:
        if not callable(recognise):
            raise TypeError("recognise must be callable")
        self._recognise = recognise

    def recognise(self, lines: Sequence[str]) -> RecogniseResult:
        return _coerce_result(self._recognise(_as_lines(lines)))


class NullRecognizer:
    """Safe default until B1's recogniser is wired in.

    Returning an explicit unknown result means B3 routes records to B2 rather
    than silently guessing a pipeline. ``reason_code`` distinguishes this
    configuration state from a genuine format miss.
    """

    def recognise(self, lines: Sequence[str]) -> RecogniseResult:
        return RecogniseResult.unknown(
            "B1 recogniser is not configured",
            reason_code="not_configured",
        )


class FakeRecognizer:
    """Deterministic test double for B2/B3 unit tests."""

    def __init__(self, result: RecogniseResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    def recognise(self, lines: Sequence[str]) -> RecogniseResult:
        self.calls.append(_as_lines(lines))
        return self.result


def load_b1_recognizer(
    target: str,
    *,
    allowed_prefixes: Sequence[str] = DEFAULT_ALLOWED_PREFIXES,
) -> B1Recognizer:
    """Load a recogniser from an allowlisted ``module:function`` target.

    The default allowlist accepts B1's expected module locations. Tests or a
    deployment can pass a narrower or different list explicitly.

    Example:
        ``load_b1_recognizer("group_B.b1.recognizer:recognise")``
    """

    module_name, separator, attribute = target.strip().partition(":")
    if not separator or not module_name or not attribute:
        raise RecognitionError(
            "recogniser target must use the form 'module:function'"
        )

    allowed = tuple(allowed_prefixes)
    if not any(
        module_name == prefix or module_name.startswith(prefix + ".")
        for prefix in allowed
    ):
        raise RecognitionError(
            f"refusing to import recogniser module {module_name!r}; "
            "allowed prefixes: " + ", ".join(allowed)
        )

    try:
        module = importlib.import_module(module_name)
    except Exception as error:
        raise RecognitionError(
            f"could not import recogniser module {module_name!r}"
        ) from error

    try:
        function = getattr(module, attribute)
    except AttributeError as error:
        raise RecognitionError(
            f"{module_name} has no attribute {attribute!r}"
        ) from error

    if not callable(function):
        raise RecognitionError(
            f"{module_name}.{attribute} is not callable"
        )

    return B1Recognizer(function)
