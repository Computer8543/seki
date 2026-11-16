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
    name = rel_path.name
    return (
        "tests" in rel_path.parts
        or "test" in rel_path.parts
        or name == "conftest.py"
        or (len(rel_path.parts) == 1 and (name.startswith("test_") or name.endswith("_test.py")))
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


def _collect_docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            ids.add(id(node.body[0].value))
    return ids


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
        docstring_ids: set[int],
    ) -> None:
        self._rel_path_str = rel_path_str
        self._changed_lines = changed_lines
        self._check_layers = check_layers
        self._check_sql_literal = check_sql_literal
        self._check_sql_interp = check_sql_interp
        self._docstring_ids = docstring_ids
        self._sql_vars: set[str] = set()
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

    def _is_sql_expr(self, expr: ast.expr) -> bool:
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return _SQL_PATTERN.search(expr.value) is not None
        return isinstance(expr, ast.Name) and expr.id in self._sql_vars

    def visit_Assign(self, node: ast.Assign) -> None:
        if (
            isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and _SQL_PATTERN.search(node.value.value) is not None
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._sql_vars.add(target.id)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if self._check_layers and any(
            "database" in alias.name.split(".") for alias in node.names
        ):
            self._add(
                "LAY-001",
                "Layer boundary violation: restricted layer imports 'database' directly.",
                node.lineno,
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self._check_layers and (
            "database" in (node.module or "").split(".")
            or any("database" in alias.name.split(".") for alias in node.names)
        ):
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

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if (
            self._check_sql_interp
            and isinstance(node.op, ast.Mod | ast.Add)
            and (self._is_sql_expr(node.left) or self._is_sql_expr(node.right))
        ):
            self._add(
                "SQL-002",
                "Potential SQL injection via string concatenation or '%' formatting.",
                node.lineno,
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            self._check_sql_interp
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and self._is_sql_expr(node.func.value)
        ):
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
            and id(node) not in self._docstring_ids
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
        docstring_ids=_collect_docstring_ids(tree),
    )
    scanner.visit(tree)
    return scanner.findings
