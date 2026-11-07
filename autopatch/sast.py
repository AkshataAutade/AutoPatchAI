"""Source Code Scanner - SAST (Flow step E).
Performs static Abstract Syntax Tree (AST) analysis and lexical secret scanning
without executing the source code.
"""
import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

DEFAULT_EXCLUDES = {".git", "__pycache__", "venv", ".venv", "tests", "node_modules", ".autopatch"}

_SECRET_ASSIGN = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*(['"])(.{4,}?)\2\s*(#.*)?$""")
_SECRET_NAME = re.compile(r"(password|passwd|secret|api_?key|token|auth_token|access_key)", re.I)


def _is_str(node: Any) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _flatten_add(node: ast.AST) -> List[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _dynamic_sql(arg: ast.AST) -> bool:
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        leaves = _flatten_add(arg)
        return any(_is_str(x) for x in leaves) and any(not _is_str(x) for x in leaves)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        return _is_str(arg.left)
    if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format" and _is_str(arg.func.value)):
        return True
    return False


def _dynamic_cmd(arg: ast.AST) -> bool:
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        leaves = _flatten_add(arg)
        return any(not _is_str(x) for x in leaves)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
        return True
    return False


class SASTScanner:
    """Static Application Security Testing scanner for Python source code."""

    def __init__(self, excludes: Optional[Set[str]] = None, disabled_rules: Optional[Set[str]] = None):
        self.excludes = excludes or set(DEFAULT_EXCLUDES)
        self.disabled_rules = disabled_rules or set()

    def scan_source(self, source: str, rel_path: str) -> Optional[List[Dict[str, Any]]]:
        """Scan a single source string and return raw SAST findings or None on parse failure."""
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return None

        lines = source.splitlines()
        findings: List[Dict[str, Any]] = []

        def add(rule_id: str, node: ast.AST, key: str):
            if rule_id in self.disabled_rules:
                return
            line_no = getattr(node, "lineno", 1)
            col = getattr(node, "col_offset", 0)
            snippet = lines[line_no - 1].strip()[:140] if line_no - 1 < len(lines) else ""
            findings.append({
                "rule_id": rule_id,
                "scanner_type": "SAST",
                "file": rel_path,
                "line": line_no,
                "col": col,
                "snippet": snippet,
                "key": key,
            })

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func

            # AP001: SQL Injection
            if (isinstance(fn, ast.Attribute) and fn.attr in ("execute", "executemany")
                    and node.args and _dynamic_sql(node.args[0])):
                add("AP001", node, ast.dump(node))

            # AP002: eval() / exec() on dynamic input
            if (isinstance(fn, ast.Name) and fn.id in ("eval", "exec")
                    and node.args and not _is_str(node.args[0])):
                add("AP002", node, ast.dump(node))

            # AP003: Weak hashing (md5 / sha1)
            if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "hashlib" and fn.attr in ("md5", "sha1")):
                add("AP003", node, ast.dump(node))

            # AP004: yaml.load without safe Loader
            if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "yaml" and fn.attr == "load"
                    and len(node.args) == 1 and not any(k.arg == "Loader" for k in node.keywords)):
                add("AP004", node, ast.dump(node))

            # AP005: verify=False TLS validation
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    add("AP005", node, ast.dump(node))

            # AP007: Command injection via os.system or shell=True
            if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "os" and fn.attr == "system"
                    and node.args and _dynamic_cmd(node.args[0])):
                add("AP007", node, ast.dump(node))

            if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "subprocess" and fn.attr in ("Popen", "run", "call", "check_output")):
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                                 for k in node.keywords)
                if shell_true and node.args and _dynamic_cmd(node.args[0]):
                    add("AP007", node, ast.dump(node))

        # AP006: Hardcoded secrets
        if "AP006" not in self.disabled_rules:
            for i, line in enumerate(lines, 1):
                m = _SECRET_ASSIGN.match(line)
                if m and _SECRET_NAME.search(m.group(1)):
                    findings.append({
                        "rule_id": "AP006",
                        "scanner_type": "SAST",
                        "file": rel_path,
                        "line": i,
                        "col": 0,
                        "snippet": f'{m.group(1)} = "****"',
                        "key": m.group(1),
                    })

        return findings

    def scan_tree(self, root: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Walk root and run SAST analysis on all Python files."""
        raw: List[Dict[str, Any]] = []
        skipped: List[str] = []

        for p in sorted(root.rglob("*.py")):
            rel = p.relative_to(root)
            if any(part in self.excludes for part in rel.parts[:-1]):
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except Exception:
                skipped.append(rel.as_posix())
                continue

            found = self.scan_source(content, rel.as_posix())
            if found is None:
                skipped.append(rel.as_posix())
                continue
            raw.extend(found)

        return raw, skipped


# Global function for backwards compatibility
def scan_source(source: str, rel: str) -> Optional[List[Dict[str, Any]]]:
    scanner = SASTScanner()
    return scanner.scan_source(source, rel)

