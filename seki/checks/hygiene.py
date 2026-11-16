"""Hygiene and FinOps static checks (HYG-001, HYG-002, FIN-001)."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from pathlib import Path

from seki.config import SekiConfig
from seki.primitives import ScrubbedFinding, make_finding

_SENSITIVE_NAME_RE: re.Pattern[str] = re.compile(
    r"(?:password|passwd|secret|api_key|apikey|private_key|access_key|token)",
    re.IGNORECASE,
)
_LOGGER_METHODS: frozenset[str] = frozenset(
    {"debug", "info", "warning", "error", "critical", "exception", "log"}
)
_PINNED_REQ_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_.\-\[\]]+==[^\s>=<~!]+$")
_BLOCKED_CLOUD_SDKS: frozenset[str] = frozenset(
    {
        "boto3",
        "botocore",
        "openai",
        "anthropic",
        "stripe",
        "twilio",
        "pinecone",
        "cohere",
        "replicate",
    }
)


def _is_test_path(rel_path: Path) -> bool:
    return (
        "tests" in rel_path.parts
        or rel_path.name.startswith("test_")
        or rel_path.name.endswith("_test.py")
    )


def _in_changed_lines(lineno: int, changed_lines: set[int] | None) -> bool:
    return changed_lines is None or lineno in changed_lines


def _scan_requirements(
    source: str,
    rel_path_str: str,
    changed_lines: set[int] | None,
) -> list[ScrubbedFinding]:
    findings: list[ScrubbedFinding] = []
    for lineno, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip().removesuffix("\\").strip()
        if not line or line.startswith(("-r", "-c", "--")):
            continue
        pkg_spec = line.split(";", 1)[0].strip()
        if not _PINNED_REQ_RE.match(pkg_spec) and _in_changed_lines(lineno, changed_lines):
            findings.append(
                make_finding(
                    rule_id="HYG-002",
                    message="Unpinned dependency in requirements file; pin strictly with '=='.",
                    file_path=rel_path_str,
                    line=lineno,
                )
            )
    return findings


def _is_log_or_print(node: ast.Call) -> bool:
    return (isinstance(node.func, ast.Name) and node.func.id == "print") or (
        isinstance(node.func, ast.Attribute) and node.func.attr in _LOGGER_METHODS
    )


def _sensitive_ref_line(
    nodes: Iterable[ast.AST],
    parent_lineno: int,
    changed_lines: set[int] | None,
) -> int | None:
    for root in nodes:
        for sub in ast.walk(root):
            if isinstance(sub, ast.Name):
                ident = sub.id
            elif isinstance(sub, ast.Attribute):
                ident = sub.attr
            else:
                continue
            if _SENSITIVE_NAME_RE.search(ident) is not None and (
                changed_lines is None
                or sub.lineno in changed_lines
                or parent_lineno in changed_lines
            ):
                return sub.lineno
    return None


def _is_blocked_sdk_name(module_name: str) -> bool:
    top = module_name.split(".", 1)[0]
    return (
        top in _BLOCKED_CLOUD_SDKS
        or module_name == "google.cloud"
        or module_name.startswith("google.cloud.")
    )


def _is_blocked_sdk_from(node: ast.ImportFrom) -> bool:
    module = node.module or ""
    return node.level == 0 and (
        _is_blocked_sdk_name(module)
        or (module == "google" and any(alias.name == "cloud" for alias in node.names))
    )


def _is_blocked_sdk_import(node: ast.Import | ast.ImportFrom) -> bool:
    if isinstance(node, ast.Import):
        return any(_is_blocked_sdk_name(alias.name) for alias in node.names)
    return _is_blocked_sdk_from(node)


def scan_hygiene(
    source: str,
    rel_path: Path,
    config: SekiConfig,
    changed_lines: set[int] | None = None,
) -> list[ScrubbedFinding]:
    """Scan requirements files and Python modules for hygiene and FinOps violations."""
    if rel_path.name.startswith("requirements") and rel_path.name.endswith(".txt"):
        return (
            _scan_requirements(source, rel_path.as_posix(), changed_lines)
            if "HYG-002" in config.enabled_rules
            else []
        )

    if rel_path.suffix != ".py" or _is_test_path(rel_path):
        return []

    check_hyg001 = "HYG-001" in config.enabled_rules
    check_fin001 = (
        "FIN-001" in config.enabled_rules
        or "zero-budget" in config.presets
        or config.budget_ceiling_usd == 0.0
    )
    if not (check_hyg001 or check_fin001):
        return []

    try:
        tree = ast.parse(source, filename=rel_path.as_posix())
    except SyntaxError:
        return []

    findings: list[ScrubbedFinding] = []
    rel_path_str = rel_path.as_posix()

    for node in ast.walk(tree):
        if check_hyg001 and isinstance(node, ast.Call) and _is_log_or_print(node):
            hit_line = _sensitive_ref_line(
                (*node.args, *(kw.value for kw in node.keywords)),
                node.lineno,
                changed_lines,
            )
            if hit_line is not None:
                findings.append(
                    make_finding(
                        rule_id="HYG-001",
                        message="Potential secret variable exposed in logging or print call.",
                        file_path=rel_path_str,
                        line=hit_line,
                    )
                )
        elif (
            check_hyg001
            and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name == "__repr__"
        ):
            hit_line = _sensitive_ref_line(node.body, node.lineno, changed_lines)
            if hit_line is not None:
                findings.append(
                    make_finding(
                        rule_id="HYG-001",
                        message="Potential secret attribute or variable exposed in __repr__.",
                        file_path=rel_path_str,
                        line=hit_line,
                    )
                )
        elif (
            check_fin001
            and isinstance(node, ast.Import | ast.ImportFrom)
            and _is_blocked_sdk_import(node)
            and _in_changed_lines(node.lineno, changed_lines)
        ):
            findings.append(
                make_finding(
                    rule_id="FIN-001",
                    message="Paid cloud/AI SDK import violates zero-budget policy.",
                    file_path=rel_path_str,
                    line=node.lineno,
                )
            )

    return findings
