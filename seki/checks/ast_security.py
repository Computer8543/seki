"""Pure-stdlib AST anti-reward-hacking and import-time side-effect engine (AST-001..003)."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from seki.primitives import ScrubbedFinding, make_finding

_PRAGMA_RE = re.compile(r"#\s*pragma:\s*no\s+(cover|branch)")
_SUBPROCESS_CALLS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_SOCKET_CALLS = frozenset({"socket", "create_connection"})


def _is_test_path(rel_path: Path) -> bool:
    """Return True when rel_path points to test code exempt from AST production rules."""
    name = rel_path.name
    return (
        "tests" in rel_path.parts
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _line_in_scope(lineno: int, changed_lines: set[int] | None) -> bool:
    return changed_lines is None or lineno in changed_lines


def _is_type_checking_test(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id == "TYPE_CHECKING") or (
        isinstance(node, ast.Attribute) and node.attr == "TYPE_CHECKING"
    )


def _is_main_guard(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
        and len(node.comparators) == 1
        and (
            (
                isinstance(node.left, ast.Name)
                and node.left.id == "__name__"
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value == "__main__"
            )
            or (
                isinstance(node.comparators[0], ast.Name)
                and node.comparators[0].id == "__name__"
                and isinstance(node.left, ast.Constant)
                and node.left.value == "__main__"
            )
        )
    )


def _is_protocol_base(base: ast.expr) -> bool:
    target = base.value if isinstance(base, ast.Subscript) else base
    return (isinstance(target, ast.Name) and target.id == "Protocol") or (
        isinstance(target, ast.Attribute) and target.attr == "Protocol"
    )


def _is_protocol_class(node: ast.ClassDef) -> bool:
    return any(_is_protocol_base(base) for base in node.bases)


def _is_stub_return(val: ast.expr | None) -> bool:
    return (
        val is None
        or (isinstance(val, ast.Constant) and (val.value is None or isinstance(val.value, bool)))
        or (isinstance(val, ast.Dict) and not val.keys and not val.values)
        or (isinstance(val, ast.List) and not val.elts)
    )


def _is_not_implemented_raise(stmt: ast.Raise) -> bool:
    exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
    return (isinstance(exc, ast.Name) and exc.id == "NotImplementedError") or (
        isinstance(exc, ast.Attribute) and exc.attr == "NotImplementedError"
    )


def _is_stub_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Pass)
        or (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis
        )
        or (isinstance(stmt, ast.Return) and _is_stub_return(stmt.value))
        or (isinstance(stmt, ast.Raise) and _is_not_implemented_raise(stmt))
    )


def _attr_chain_has_name(expr: ast.expr, target: str) -> bool:
    while isinstance(expr, ast.Attribute):
        if expr.attr == target:
            return True
        expr = expr.value
    return isinstance(expr, ast.Name) and expr.id == target


def _side_effect_call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name) and func.id in {"open", "urlopen"}:
        return func.id
    if isinstance(func, ast.Attribute):
        if func.attr in {"urlopen", "connect"}:
            return func.attr
        if func.attr in _SOCKET_CALLS and _attr_chain_has_name(func.value, "socket"):
            return f"socket.{func.attr}"
        if func.attr in _SUBPROCESS_CALLS and _attr_chain_has_name(func.value, "subprocess"):
            return f"subprocess.{func.attr}"
    return None


class _AstSecurityVisitor(ast.NodeVisitor):
    """Single-pass AST visitor collecting AST-001, AST-002 (stubs), and AST-003 findings."""

    def __init__(self, file_path: str, changed_lines: set[int] | None) -> None:
        self.file_path = file_path
        self.changed_lines = changed_lines
        self.findings: list[ScrubbedFinding] = []
        self._in_protocol = False
        self._module_scope = True

    def _visit_stmts(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.visit(stmt)

    def _check_stub_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        body = node.body
        if (
            len(body) > 1
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if len(body) == 1 and _is_stub_stmt(body[0]):
            stmt = body[0]
            if (
                _line_in_scope(stmt.lineno, self.changed_lines)
                or _line_in_scope(node.lineno, self.changed_lines)
            ):
                self.findings.append(
                    make_finding(
                        "AST-002",
                        f"Stub/no-op function '{node.name}' detected",
                        self.file_path,
                        line=stmt.lineno,
                    )
                )

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if not self._in_protocol:
            self._check_stub_function(node)
        prev_protocol = self._in_protocol
        prev_module = self._module_scope
        self._in_protocol = False
        self._module_scope = False
        self.generic_visit(node)
        self._in_protocol = prev_protocol
        self._module_scope = prev_module

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_test(node.test):
            self._visit_stmts(node.orelse)
            return
        if self._module_scope and _is_main_guard(node.test):
            self._module_scope = False
            self._visit_stmts(node.body)
            self._module_scope = True
            self._visit_stmts(node.orelse)
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev_protocol = self._in_protocol
        prev_module = self._module_scope
        self._in_protocol = _is_protocol_class(node)
        self._module_scope = False
        self.generic_visit(node)
        self._in_protocol = prev_protocol
        self._module_scope = prev_module

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        prev_module = self._module_scope
        self._module_scope = False
        self.generic_visit(node)
        self._module_scope = prev_module

    def visit_Assert(self, node: ast.Assert) -> None:
        if _line_in_scope(node.lineno, self.changed_lines):
            self.findings.append(
                make_finding(
                    "AST-001",
                    "Production 'assert' statement is stripped under python -O",
                    self.file_path,
                    line=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._module_scope:
            effect = _side_effect_call_name(node.func)
            if effect is not None and _line_in_scope(node.lineno, self.changed_lines):
                self.findings.append(
                    make_finding(
                        "AST-003",
                        f"Import-time side effect '{effect}' at module scope",
                        self.file_path,
                        line=node.lineno,
                    )
                )
        self.generic_visit(node)


def scan_ast_security(
    source: str,
    rel_path: Path,
    changed_lines: set[int] | None = None,
) -> list[ScrubbedFinding]:
    """Scan Python source for AST-001, AST-002, and AST-003 violations."""
    if _is_test_path(rel_path):
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    file_path = rel_path.as_posix()
    visitor = _AstSecurityVisitor(file_path=file_path, changed_lines=changed_lines)
    visitor.visit(tree)
    findings = visitor.findings

    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if (
            tok.type == tokenize.COMMENT
            and _PRAGMA_RE.search(tok.string)
            and _line_in_scope(tok.start[0], changed_lines)
        ):
            findings.append(
                make_finding(
                    "AST-002",
                    "Unauthorized coverage pragma comment",
                    file_path,
                    line=tok.start[0],
                )
            )

    findings.sort(key=lambda finding: (finding.line, finding.rule_id))
    return findings
