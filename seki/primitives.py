"""Fail-closed domain primitives and secret-scrubbing boundaries for seki."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Generic, NoReturn, SupportsIndex, TypeVar, cast

T = TypeVar("T")

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_PEM_MARKER_RE = re.compile(
    r"(?:-----)?(?:BEGIN|END) [A-Z0-9 ]*PRIVATE KEY(?:-----)?"
)
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])"
)
_API_KEY_RE = re.compile(
    r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9_]{20,}\b"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class _ConstructorToken:
    """Module-private capability token guarding Domain Primitive constructors."""


_TOKEN = _ConstructorToken()


@dataclass(frozen=True)
class SekiError:
    """Structured fail-closed domain or configuration error."""

    code: str
    message: str
    exit_code: int = 3


@dataclass(frozen=True)
class Result(Generic[T]):
    """Explicit success/error container enforcing fail-closed error handling."""

    _value: T | None = None
    error: SekiError | None = None

    def is_ok(self) -> bool:
        """Return True when this Result holds a value and no error."""
        return self.error is None

    def is_err(self) -> bool:
        """Return True when this Result holds a SekiError."""
        return self.error is not None

    @property
    def value(self) -> T:
        """Return the wrapped value or raise ValueError when holding an error."""
        if self.error is not None:
            raise ValueError(f"Result holds error ({self.error.code}): {self.error.message}")
        return cast(T, self._value)

    def unwrap(self) -> T:
        """Return the wrapped value or raise ValueError when holding an error."""
        return self.value

    @classmethod
    def ok(cls, val: T) -> Result[T]:
        """Construct a successful Result containing val."""
        return cls(_value=val, error=None)

    @classmethod
    def err(cls, err: SekiError) -> Result[Any]:
        """Construct a failed Result containing err."""
        return cls(_value=None, error=err)


def scrub_sensitive_text(text: str) -> str:
    """Redact PEM private keys, JWTs, API tokens, and IPv4 literals from text."""
    scrubbed = _PEM_BLOCK_RE.sub("[REDACTED_PEM]", text)
    scrubbed = _PEM_MARKER_RE.sub("[REDACTED_PEM]", scrubbed)
    scrubbed = _JWT_RE.sub("[REDACTED_JWT]", scrubbed)
    scrubbed = _API_KEY_RE.sub("[REDACTED_SECRET]", scrubbed)
    return _IPV4_RE.sub("[REDACTED_IP]", scrubbed)


class ReadOnceSecretSnippet:
    """Single-use secret carrier blocking copy, pickle, subclassing, and repr leaks."""

    __slots__ = ("_consumed", "_value")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ReadOnceSecretSnippet cannot be subclassed")

    def __init__(self, _value: str = "", _token: object = None) -> None:
        if _token is not _TOKEN:
            raise PermissionError(
                "ReadOnceSecretSnippet cannot be instantiated directly; use create()"
            )
        self._value = _value
        self._consumed = False

    @classmethod
    def create(cls, raw_secret: str) -> Result[ReadOnceSecretSnippet]:
        """Wrap a raw secret string in a read-once carrier."""
        return Result.ok(cls(_value=raw_secret, _token=_TOKEN))

    def consume(self) -> str:
        """Return the secret once, wiping internal state and blocking subsequent reads."""
        if self._consumed:
            raise RuntimeError("ReadOnceSecretSnippet has already been consumed")
        secret = self._value
        self._value = ""
        self._consumed = True
        return secret

    def __repr__(self) -> str:
        return "ReadOnceSecretSnippet(<redacted>)"

    def __str__(self) -> str:
        return "ReadOnceSecretSnippet(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ReadOnceSecretSnippet cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ReadOnceSecretSnippet cannot be pickled")

    def __copy__(self) -> NoReturn:
        raise TypeError("ReadOnceSecretSnippet cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("ReadOnceSecretSnippet cannot be copied")


@dataclass(frozen=True)
class ScrubbedFinding:
    """Immutable check finding whose message is scrubbed at construction time."""

    rule_id: str
    message: str
    file_path: str
    line: int = 1
    severity: str = "error"
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _TOKEN:
            raise PermissionError(
                "ScrubbedFinding cannot be instantiated directly; use ScrubbedFinding.create()"
            )
        object.__setattr__(self, "message", scrub_sensitive_text(self.message))

    @classmethod
    def create(
        cls,
        *,
        rule_id: str,
        message: str,
        file_path: str,
        line: int = 1,
        severity: str = "error",
        snippet: ReadOnceSecretSnippet | None = None,
    ) -> Result[ScrubbedFinding]:
        """Consume any optional secret snippet and return a scrubbed immutable finding."""
        if snippet is not None:
            _ = snippet.consume()
        return Result.ok(
            cls(
                rule_id=rule_id,
                message=message,
                file_path=file_path,
                line=line,
                severity=severity,
                _token=_TOKEN,
            )
        )


def make_finding(
    rule_id: str,
    message: str,
    file_path: str,
    line: int = 1,
    severity: str = "error",
    snippet: ReadOnceSecretSnippet | None = None,
) -> ScrubbedFinding:
    """Create and unwrap a ScrubbedFinding in a single step for check modules."""
    return ScrubbedFinding.create(
        rule_id=rule_id,
        message=message,
        file_path=file_path,
        line=line,
        severity=severity,
        snippet=snippet,
    ).unwrap()
