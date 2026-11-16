"""Architectural layer boundary and SQL isolation checks (LAY-001, SQL-001, SQL-002)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from seki.config import SekiConfig
from seki.primitives import ScrubbedFinding, make_finding

_RESTRICTED_LAYERS: frozenset[str] = frozenset({"api", "services", "workers"})
_SQL_EXEMPT_DIRS: frozenset[str] = frozenset({"repositories", "migrations"})
_SQL_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:SELECT\s+.*?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b",
    re.IGNORECASE | re.DOTALL,
)


def _is_test_path(rel_path: Path) -> bool:
    return (
        "tests" in rel_path.parts
        or rel_path.name.startswith("test_")
        or rel_path.name.endswith("_test.py")
    )


def _is_restricted_layer(rel_path: Path) -> bool:
    parents = rel_path.parts[:-1]
    return any(part in _RESTRICTED_LAYERS for part in parents) and not any(
        part in _SQL_EXEMPT_DIRS or part == "database" for part in parents
    )


def _in_changed_lines(lineno: int, changed_lines: set[int] | None) -> bool:
    return changed_lines is None or lineno in changed_lines


def _joined_str_preview(node: ast.JoinedStr) -> str:
    return "".join(
        part.value
        if isinstance(part, ast.Constant) and isinstance(part.value, str)
        else "_expr_"
        for part in node.values
    )


def _is_sql_format_call(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str)
        and _SQL_PATTERN.search(node.func.value.value) is not None
    )


class _LayerScanner(ast.NodeVisitor):
    """AST visitor detecting layer boundary imports, raw SQL literals, and SQL interpolation."""

    def __init__(
        self,
        *,
        rel_path_str: str,
        changed_lines: set[int] | None,
        check_layers: bool,
        check_sql_literal: bool,
        check_sql_interp: bool,
    ) -> None:
        self._rel_path_str = rel_path_str
        self._changed_lines = changed_lines
        self._check_layers = check_layers
        self._check_sql_literal = check_sql_literal
        self._check_sql_interp = check_sql_interp
        self.findings: list[ScrubbedFinding] = []

    def _add(self, rule_id: str, message: str, line: int) -> None:
        if _in_changed_lines(line, self._changed_lines):
            self.findings.append(
                make_finding(
                    rule_id=rule_id,
                    message=message,
                    file_path=self._rel_path_str,
                    line=line,
                )
            )

    def visit_Import(self, node: ast.Import) -> None:
        if self._check_layers and any(
            alias.name.split(".")[0] == "database" for alias in node.names
        ):
            self._add(
                "LAY-001",
                "Layer boundary violation: restricted layer imports 'database' directly.",
                node.lineno,
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self._check_layers and (node.module or "").split(".")[0] == "database":
            self._add(
                "LAY-001",
                "Layer boundary violation: restricted layer imports from 'database' directly.",
                node.lineno,
            )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        if self._check_sql_interp and _SQL_PATTERN.search(_joined_str_preview(node)) is not None:
            self._add(
                "SQL-002",
                "Potential SQL injection via f-string interpolation.",
                node.lineno,
            )
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                self.visit(part.value)

    def visit_Call(self, node: ast.Call) -> None:
        if self._check_sql_interp and _is_sql_format_call(node):
            self._add(
                "SQL-002",
                "Potential SQL injection via str.format() interpolation.",
                node.lineno,
            )
            for child in (*node.args, *(kw.value for kw in node.keywords)):
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if (
            self._check_sql_literal
            and isinstance(node.value, str)
            and _SQL_PATTERN.search(node.value) is not None
        ):
            self._add(
                "SQL-001",
                "Raw SQL literal found outside repositories/ or migrations/.",
                node.lineno,
            )


def scan_layers(
    source: str,
    rel_path: Path,
    config: SekiConfig,
    changed_lines: set[int] | None = None,
) -> list[ScrubbedFinding]:
    """Scan Python source for architectural layer violations and SQL boundary/injection issues."""
    if rel_path.suffix != ".py" or _is_test_path(rel_path):
        return []

    check_layers = (
        "LAY-001" in config.enabled_rules or "layered-backend" in config.presets
    ) and _is_restricted_layer(rel_path)
    check_sql_literal = (
        "SQL-001" in config.enabled_rules or "layered-backend" in config.presets
    ) and not any(part in _SQL_EXEMPT_DIRS for part in rel_path.parts[:-1])
    check_sql_interp = "SQL-002" in config.enabled_rules or "layered-backend" in config.presets
    if not (check_layers or check_sql_literal or check_sql_interp):
        return []

    try:
        tree = ast.parse(source, filename=rel_path.as_posix())
    except SyntaxError:
        return []

    scanner = _LayerScanner(
        rel_path_str=rel_path.as_posix(),
        changed_lines=changed_lines,
        check_layers=check_layers,
        check_sql_literal=check_sql_literal,
        check_sql_interp=check_sql_interp,
    )
    scanner.visit(tree)
    return scanner.findings
