"""Static security scanner: AST rules plus a secrets check. Never executes the code."""
import ast
import re

DEFAULT_EXCLUDES = {".git", "__pycache__", "venv", ".venv", "tests", "node_modules", ".autopatch"}

_SECRET_ASSIGN = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*(['"])(.{4,}?)\2\s*(#.*)?$""")
_SECRET_NAME = re.compile(r"(password|passwd|secret|api_?key|token)", re.I)


def _is_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _flatten_add(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


def _dynamic_sql(arg):
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


def scan_source(source: str, rel: str):
    """Return raw findings (dicts) for one file, or None if it cannot be parsed."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    lines = source.splitlines()
    out = []

    def add(rule_id, node, key):
        out.append(dict(rule_id=rule_id, file=rel, line=node.lineno, col=node.col_offset,
                        snippet=lines[node.lineno - 1].strip()[:140], key=key))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr == "execute"
                and node.args and _dynamic_sql(node.args[0])):
            add("AP001", node, ast.dump(node))
        if isinstance(fn, ast.Name) and fn.id == "eval" and node.args and not _is_str(node.args[0]):
            add("AP002", node, ast.dump(node))
        if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                and fn.value.id == "hashlib" and fn.attr in ("md5", "sha1")):
            add("AP003", node, ast.dump(node))
        if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                and fn.value.id == "yaml" and fn.attr == "load"
                and len(node.args) == 1 and not any(k.arg == "Loader" for k in node.keywords)):
            add("AP004", node, ast.dump(node))
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                add("AP005", node, ast.dump(node))

    for i, line in enumerate(lines, 1):
        m = _SECRET_ASSIGN.match(line)
        if m and _SECRET_NAME.search(m.group(1)):
            out.append(dict(rule_id="AP006", file=rel, line=i, col=0,
                            snippet=f'{m.group(1)} = "****"', key=m.group(1)))
    return out
