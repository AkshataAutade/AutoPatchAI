"""Rule-based repair engine. Each fixer returns new source text, or None when the
code does not match a pattern that can be repaired safely (then it goes to manual review)."""
import ast
import json
import re

from .findings import make_fingerprint


class Src:
    """Byte-accurate source editing using AST line/column offsets."""

    def __init__(self, text):
        self.b = text.encode("utf-8")
        self.starts = [0] + [i + 1 for i, ch in enumerate(self.b) if ch == 10]

    def off(self, line, col):
        return self.starts[line - 1] + col

    def span(self, node):
        return (self.off(node.lineno, node.col_offset),
                self.off(node.end_lineno, node.end_col_offset))

    def replace(self, s, e, new):
        self.b = self.b[:s] + new.encode("utf-8") + self.b[e:]

    def result(self):
        return self.b.decode("utf-8")


def _find_call(tree, f):
    # Match position AND fingerprint: an outer call such as hashlib.md5(x).hexdigest()
    # starts at the same position as the inner call that was actually flagged.
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and n.lineno == f.line and n.col_offset == f.col
                and make_fingerprint(f.rule_id, f.file, ast.dump(n)) == f.fingerprint):
            return n
    return None


def _is_str(n):
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


def _parts(arg):
    """Split a dynamic SQL expression into (literal pieces, expressions), or None."""
    if isinstance(arg, ast.JoinedStr):
        lits, exprs = [""], []
        for v in arg.values:
            if isinstance(v, ast.Constant):
                lits[-1] += str(v.value)
            elif isinstance(v, ast.FormattedValue):
                if v.format_spec is not None or v.conversion != -1:
                    return None
                exprs.append(v.value)
                lits.append("")
            else:
                return None
        return lits, exprs
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        lits, exprs = [""], []

        def walk(n):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                walk(n.left)
                walk(n.right)
            elif _is_str(n):
                lits[-1] += n.value
            else:
                exprs.append(n)
                lits.append("")
        walk(arg)
        return lits, exprs
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod) and _is_str(arg.left):
        tpl = arg.left.value
        params = list(arg.right.elts) if isinstance(arg.right, ast.Tuple) else [arg.right]
        if tpl.count("%") != tpl.count("%s") or tpl.count("%s") != len(params):
            return None
        return tpl.split("%s"), params
    if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format" and _is_str(arg.func.value)):
        tpl = arg.func.value.value
        if arg.keywords or any(isinstance(a, ast.Starred) for a in arg.args):
            return None
        if "{{" in tpl or "}}" in tpl:
            return None
        if any(t != "{}" for t in re.findall(r"\{[^{}]*\}", tpl)):
            return None
        if tpl.count("{}") != len(arg.args):
            return None
        return tpl.split("{}"), list(arg.args)
    return None


def fix_sqli(text, f, ctx):
    tree = ast.parse(text)
    call = _find_call(tree, f)
    if call is None or len(call.args) != 1 or call.keywords:
        return None
    parts = _parts(call.args[0])
    if parts is None:
        return None
    lits, exprs = list(parts[0]), parts[1]
    if not exprs:
        return None
    for i in range(len(exprs)):  # drop the quotes that wrapped an inlined value
        left, right = lits[i], lits[i + 1]
        if left and right and left[-1] in "'\"" and right[0] == left[-1]:
            lits[i], lits[i + 1] = left[:-1], right[1:]
    for i in range(len(exprs)):  # quotes we could not pair up: too risky to guess
        if (lits[i] and lits[i][-1] in "'\"") or (lits[i + 1] and lits[i + 1][0] in "'\""):
            return None
    for i in range(len(exprs)):  # a value inside a quoted string (e.g. LIKE '%x%') cannot
        prefix = "".join(lits[:i + 1])  # become a bare placeholder; leave it to a human
        if prefix.count("'") % 2 or prefix.count('"') % 2:
            return None
    tpl = lits[0]
    for i in range(len(exprs)):
        tpl += ctx["placeholder"] + lits[i + 1]
    params = ", ".join(ast.unparse(e) for e in exprs) + ("," if len(exprs) == 1 else "")
    src = Src(text)
    s, e = src.span(call.args[0])
    src.replace(s, e, f"{json.dumps(tpl)}, ({params})")
    return src.result()


def _ensure_import(text, module):
    if re.search(rf"^import {module}\s*$", text, re.M):
        return text
    body = ast.parse(text).body
    lines = text.split("\n")
    idx, i = 0, 0
    if body and isinstance(body[0], ast.Expr) and _is_str(getattr(body[0], "value", None)):
        idx, i = body[0].end_lineno, 1
    while i < len(body) and isinstance(body[i], (ast.Import, ast.ImportFrom)):
        idx = body[i].end_lineno
        i += 1
    lines.insert(idx, f"import {module}")
    return "\n".join(lines)


def fix_eval(text, f, ctx):
    call = _find_call(ast.parse(text), f)
    if (call is None or not isinstance(call.func, ast.Name) or call.func.id != "eval"
            or len(call.args) != 1 or call.keywords):
        return None
    src = Src(text)
    s, e = src.span(call.func)
    src.replace(s, e, "ast.literal_eval")
    return _ensure_import(src.result(), "ast")


def _rename_attr(text, f, new):
    call = _find_call(ast.parse(text), f)
    if call is None or not isinstance(call.func, ast.Attribute):
        return None
    src = Src(text)
    s, e = src.span(call.func)
    old = call.func.attr.encode()
    if src.b[e - len(old):e] != old:
        return None
    src.replace(e - len(old), e, new)
    return src.result()


def fix_weak_hash(text, f, ctx):
    return _rename_attr(text, f, "sha256")


def fix_yaml(text, f, ctx):
    return _rename_attr(text, f, "safe_load")


def fix_tls(text, f, ctx):
    call = _find_call(ast.parse(text), f)
    if call is None:
        return None
    for kw in call.keywords:
        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            src = Src(text)
            s, e = src.span(kw)
            src.replace(s, e, "verify=True")
            return src.result()
    return None


FIXERS = {
    "AP001": fix_sqli,
    "AP002": fix_eval,
    "AP003": fix_weak_hash,
    "AP004": fix_yaml,
    "AP005": fix_tls,
}
