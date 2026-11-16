"""Polyglot hygiene engine for GitHub Actions, SQL RLS migrations, and client secrets."""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Sequence
from pathlib import Path

from seki.config import SekiConfig
from seki.primitives import ReadOnceSecretSnippet, ScrubbedFinding, make_finding

_DEFAULT_POLYGLOT_RULES: frozenset[str] = frozenset({"POLY-001", "POLY-002", "POLY-003"})

_SUFFIX_TO_RULE: dict[str, str] = {
    ".yml": "POLY-001",
    ".yaml": "POLY-001",
    ".sql": "POLY-002",
    ".ts": "POLY-003",
    ".tsx": "POLY-003",
    ".js": "POLY-003",
    ".jsx": "POLY-003",
    ".swift": "POLY-003",
}

_YML_WRITE_ALL_RE = re.compile(r"""^\s*permissions:\s*["']?write-all\b""")
_YML_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
_ACTION_SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-fA-F]{40}$")

_SQL_COMMENT_RE = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/")
_SQL_DESTRUCTIVE_RE = re.compile(r"\b(?:DROP\s+TABLE|TRUNCATE)\b", re.IGNORECASE)
_SQL_CREATE_TABLE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_."]+)',
    re.IGNORECASE,
)
_SQL_ALTER_RLS_RE = re.compile(
    r'ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([A-Za-z0-9_."]+)'
    r"\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    re.IGNORECASE,
)

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*")
_CLIENT_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "Detected PEM private key block in client source",
    ),
    (
        re.compile(r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b"),
        "Detected hardcoded API secret token in client source",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Detected hardcoded AWS access key ID in client source",
    ),
)


def _line_in_scope(lineno: int, changed_lines: set[int] | None) -> bool:
    return changed_lines is None or lineno in changed_lines


def _preserve_newlines(match: re.Match[str]) -> str:
    return "\n" * match.group(0).count("\n")


def _normalize_table_name(raw_name: str) -> str:
    cleaned = raw_name.replace('"', "").strip().lower()
    if "." not in cleaned:
        return f"public.{cleaned}"
    return cleaned


def _split_sql_statements(source: str) -> list[tuple[str, int]]:
    cleaned = _SQL_COMMENT_RE.sub(_preserve_newlines, source)
    statements: list[tuple[str, int]] = []
    pos = 0
    length = len(cleaned)
    while True:
        semi = cleaned.find(";", pos)
        end = length if semi == -1 else semi
        raw_chunk = cleaned[pos:end]
        stripped = raw_chunk.lstrip()
        if stripped:
            leading_ws = len(raw_chunk) - len(stripped)
            start_line = cleaned.count("\n", 0, pos + leading_ws) + 1
            statements.append((stripped, start_line))
        if semi == -1:
            break
        pos = semi + 1
    return statements


def _scan_github_actions(
    source: str,
    file_str: str,
    changed_lines: set[int] | None,
) -> list[ScrubbedFinding]:
    findings: list[ScrubbedFinding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        if not _line_in_scope(lineno, changed_lines):
            continue
        if line.lstrip().startswith("#"):
            continue
        if _YML_WRITE_ALL_RE.search(line):
            findings.append(
                make_finding(
                    "POLY-001",
                    "GitHub Actions workflow uses overly permissive 'permissions: write-all'",
                    file_str,
                    line=lineno,
                )
            )
            continue
        uses_match = _YML_USES_RE.search(line)
        if uses_match is None:
            continue
        action_ref = uses_match.group(1).strip("'\"")
        if action_ref.startswith(("./", "docker://")):
            continue
        if not _ACTION_SHA_PIN_RE.match(action_ref):
            findings.append(
                make_finding(
                    "POLY-001",
                    f"GitHub Action '{action_ref}' must be pinned to a full 40-char commit SHA",
                    file_str,
                    line=lineno,
                )
            )
    return findings


def _scan_sql_migrations(
    source: str,
    file_str: str,
    rls_allowlist: tuple[str, ...],
    changed_lines: set[int] | None,
) -> list[ScrubbedFinding]:
    findings: list[ScrubbedFinding] = []
    created_public_tables: list[tuple[str, int]] = []
    rls_enabled: set[str] = set()
    normalized_allowlist = {_normalize_table_name(name) for name in rls_allowlist}

    for stmt, start_line in _split_sql_statements(source):
        if _SQL_DESTRUCTIVE_RE.search(stmt) and _line_in_scope(start_line, changed_lines):
            findings.append(
                make_finding(
                    "POLY-002",
                    "Destructive DDL statement (DROP TABLE / TRUNCATE) blocked in SQL migration",
                    file_str,
                    line=start_line,
                )
            )
        create_match = _SQL_CREATE_TABLE_RE.search(stmt)
        if create_match is not None:
            table_name = _normalize_table_name(create_match.group(1))
            if table_name.startswith("public."):
                created_public_tables.append((table_name, start_line))
        alter_match = _SQL_ALTER_RLS_RE.search(stmt)
        if alter_match is not None:
            rls_enabled.add(_normalize_table_name(alter_match.group(1)))

    for table_name, start_line in created_public_tables:
        if (
            table_name not in rls_enabled
            and table_name not in normalized_allowlist
            and _line_in_scope(start_line, changed_lines)
        ):
            findings.append(
                make_finding(
                    "POLY-002",
                    f"Table '{table_name}' created without ENABLE ROW LEVEL SECURITY",
                    file_str,
                    line=start_line,
                )
            )

    findings.sort(key=lambda finding: finding.line)
    return findings


def _is_service_role_jwt(payload_segment: str) -> bool:
    padded = payload_segment + "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("role") == "service_role"


def _make_secret_finding(
    raw_secret: str,
    message: str,
    file_str: str,
    lineno: int,
) -> ScrubbedFinding:
    snippet = ReadOnceSecretSnippet.create(raw_secret).unwrap()
    return make_finding("POLY-003", message, file_str, line=lineno, snippet=snippet)


def _scan_client_secrets(
    source: str,
    file_str: str,
    changed_lines: set[int] | None,
) -> list[ScrubbedFinding]:
    findings: list[ScrubbedFinding] = []
    for match in _JWT_RE.finditer(source):
        lineno = source.count("\n", 0, match.start()) + 1
        if _line_in_scope(lineno, changed_lines) and _is_service_role_jwt(match.group(1)):
            findings.append(
                _make_secret_finding(
                    match.group(0),
                    "Detected JWT with privileged role 'service_role' in client source",
                    file_str,
                    lineno,
                )
            )

    for pattern, message in _CLIENT_SECRET_PATTERNS:
        for match in pattern.finditer(source):
            lineno = source.count("\n", 0, match.start()) + 1
            if _line_in_scope(lineno, changed_lines):
                findings.append(_make_secret_finding(match.group(0), message, file_str, lineno))

    findings.sort(key=lambda finding: finding.line)
    return findings


def scan_polyglot_file(
    source: str,
    rel_path: Path,
    config: SekiConfig | None = None,
    changed_lines: set[int] | None = None,
) -> list[ScrubbedFinding]:
    """Scan a single source string for POLY-001, POLY-002, or POLY-003 violations."""
    enabled_rules = _DEFAULT_POLYGLOT_RULES if config is None else config.enabled_rules
    rule_id = _SUFFIX_TO_RULE.get(rel_path.suffix.lower())
    if rule_id is None or rule_id not in enabled_rules:
        return []

    file_str = str(rel_path)
    if rule_id == "POLY-001":
        return _scan_github_actions(source, file_str, changed_lines)
    if rule_id == "POLY-002":
        rls_allowlist = () if config is None else config.rls_allowlist
        return _scan_sql_migrations(source, file_str, rls_allowlist, changed_lines)
    return _scan_client_secrets(source, file_str, changed_lines)


def scan_polyglot_files(
    files: Sequence[Path],
    config: SekiConfig | None = None,
) -> list[ScrubbedFinding]:
    """Scan a sequence of file paths for enabled polyglot hygiene violations."""
    enabled_rules = _DEFAULT_POLYGLOT_RULES if config is None else config.enabled_rules
    if not enabled_rules & _DEFAULT_POLYGLOT_RULES:
        return []

    findings: list[ScrubbedFinding] = []
    for file_path in files:
        rule_id = _SUFFIX_TO_RULE.get(file_path.suffix.lower())
        if rule_id is None or rule_id not in enabled_rules or not file_path.is_file():
            continue
        source = file_path.read_text(encoding="utf-8", errors="replace")
        findings.extend(scan_polyglot_file(source, file_path, config=config))
    return findings
