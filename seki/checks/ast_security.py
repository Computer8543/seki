"""Pure-stdlib AST anti-reward-hacking and import-time side-effect engine (AST-001..003)."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

from seki.primitives import ScrubbedFinding, make_finding

_PRAGMA_RE = re.compile(r"#\s*pragma:?\s*no\s*(?:cover|branch)", re.IGNORECASE)
_SUBPROCESS_CALLS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_SOCKET_CALLS = frozenset({"socket", "create_connection"})
_EXEMPT_DECORATORS = frozenset(
    {
        "abstractmethod",
        "abstractclassmethod",
        "abstractstaticmethod",
        "abstractproperty",
        "overload",
    }
)
_DIRECT_SIDE_EFFECTS = frozenset(
    {
        "open",
        "urlopen",
        "urllib.request.urlopen",
        "os.system",
        "os.popen",
        "os.getenv",
        "os.putenv",
    }
)


def _is_test_path(rel_path: Path) -> bool:
    """Return True when rel_path points to test code exempt from AST-001."""
    name = rel_path.name
    return (
        "tests" in rel_path.parts
        or "test" in rel_path.parts
        or name == "conftest.py"
        or (len(rel_path.parts) == 1 and (name.startswith("test_") or name.endswith("_test.py")))
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
        or (
            isinstance(val, ast.Constant)
            and (
                val.value is None
                or isinstance(val.value, bool)
                or val.value in (0, "", b"")
            )
        )
        or (isinstance(val, ast.Dict) and not val.keys and not val.values)
        or (isinstance(val, ast.List) and not val.elts)
        or (isinstance(val, ast.Tuple) and not val.elts)
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


def _is_docstring_expr(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _is_exempt_decorator(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Name):
        return target.id in _EXEMPT_DECORATORS
    if isinstance(target, ast.Attribute):
        return target.attr in _EXEMPT_DECORATORS
    return False


def _has_shadowed_type_checking(tree: ast.Module) -> bool:
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(node, ast.Name) and node.id == "TYPE_CHECKING"
            for target in stmt.targets
            for node in ast.walk(target)
        ):
            return True
        if (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == "TYPE_CHECKING"
        ):
            return True
    return False


def _resolve_expr_path(
    expr: ast.expr,
    module_aliases: dict[str, str],
    symbol_aliases: dict[str, str],
) -> str | None:
    parts: list[str] = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    parts.reverse()
    head = parts[0]
    prefix = symbol_aliases.get(head) or module_aliases.get(head) or head
    return ".".join([prefix, *parts[1:]])


def _side_effect_call_name(
    func: ast.expr,
    module_aliases: dict[str, str],
    symbol_aliases: dict[str, str],
) -> str | None:
    resolved = _resolve_expr_path(func, module_aliases, symbol_aliases)
    if resolved is not None:
        if resolved in _DIRECT_SIDE_EFFECTS or resolved.startswith("os.environ."):
            return resolved
        parts = resolved.split(".")
        tail = parts[-1]
        if tail in {"urlopen", "connect"}:
            return tail
        if tail in _SOCKET_CALLS and "socket" in parts[:-1]:
            return f"socket.{tail}"
        if tail in _SUBPROCESS_CALLS and "subprocess" in parts[:-1]:
            return f"subprocess.{tail}"
        return None
    if isinstance(func, ast.Attribute) and func.attr in {"urlopen", "connect"}:
        return func.attr
    return None


class _AstSecurityVisitor(ast.NodeVisitor):
    """Single-pass AST visitor collecting AST-001, AST-002 (stubs), and AST-003 findings."""

    def __init__(
        self,
        file_path: str,
        changed_lines: set[int] | None,
        *,
        allow_assert: bool,
        type_checking_shadowed: bool,
    ) -> None:
        self.file_path = file_path
        self.changed_lines = changed_lines
        self.allow_assert = allow_assert
        self._type_checking_shadowed = type_checking_shadowed
        self.findings: list[ScrubbedFinding] = []
        self._in_protocol = False
        self._module_scope = True
        self._module_aliases: dict[str, str] = {}
        self._symbol_aliases: dict[str, str] = {}

    def _visit_stmts(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.visit(stmt)

    def _check_stub_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        body = node.body
        if len(body) == 1 and _is_docstring_expr(body[0]):
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
            return
        if len(body) > 1 and _is_docstring_expr(body[0]):
            body = body[1:]
        if all(_is_stub_stmt(stmt) for stmt in body):
            stmt = body[0]
            if any(_line_in_scope(s.lineno, self.changed_lines) for s in body) or _line_in_scope(
                node.lineno, self.changed_lines
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
        is_exempt_decorator = any(_is_exempt_decorator(dec) for dec in node.decorator_list)
        if not self._in_protocol and not is_exempt_decorator:
            self._check_stub_function(node)
        for dec in node.decorator_list:
            self.visit(dec)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        prev_protocol = self._in_protocol
        prev_module = self._module_scope
        self._in_protocol = False
        self._module_scope = False
        self._visit_stmts(node.body)
        self._in_protocol = prev_protocol
        self._module_scope = prev_module

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname is not None:
                self._module_aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".", 1)[0]
                self._module_aliases[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module is not None:
            for alias in node.names:
                local = alias.asname or alias.name
                self._symbol_aliases[local] = f"{node.module}.{alias.name}"

    def visit_If(self, node: ast.If) -> None:
        if not self._type_checking_shadowed and _is_type_checking_test(node.test):
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
        self._in_protocol = _is_protocol_class(node)
        self.generic_visit(node)
        self._in_protocol = prev_protocol

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
        if not self.allow_assert and _line_in_scope(node.lineno, self.changed_lines):
            self.findings.append(
                make_finding(
                    "AST-001",
                    "Production 'assert' statement is stripped under python -O",
                    self.file_path,
                    line=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._module_scope:
            resolved = _resolve_expr_path(node.value, self._module_aliases, self._symbol_aliases)
            if resolved == "os.environ" and _line_in_scope(node.lineno, self.changed_lines):
                self.findings.append(
                    make_finding(
                        "AST-003",
                        "Import-time side effect 'os.environ' at module scope",
                        self.file_path,
                        line=node.lineno,
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._module_scope:
            effect = _side_effect_call_name(
                node.func, self._module_aliases, self._symbol_aliases
            )
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
    file_path = rel_path.as_posix()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        err_line = exc.lineno or 1
        if _line_in_scope(err_line, changed_lines):
            return [
                make_finding(
                    "AST-001",
                    f"SyntaxError prevents AST verification: {exc.msg}",
                    file_path,
                    line=err_line,
                )
            ]
        return []

    visitor = _AstSecurityVisitor(
        file_path=file_path,
        changed_lines=changed_lines,
        allow_assert=_is_test_path(rel_path),
        type_checking_shadowed=_has_shadowed_type_checking(tree),
    )
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
