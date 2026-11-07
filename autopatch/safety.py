"""Patch Safety Validation module (Flow step N).
Validates that generated patches are syntactically valid Python, preserve AST
integrity, do not truncate files, and do not introduce dangerous constructs.
"""
import ast
from typing import List, Tuple

from .findings import Finding

BANNED_NEW_CALLS = {"__import__", "eval", "exec", "os.system"}


class PatchSafetyValidator:
    """Validates patch safety prior to applying changes to working copy."""

    @classmethod
    def validate(cls, before_code: str, after_code: str, finding: Finding) -> Tuple[bool, List[str]]:
        issues: List[str] = []

        if not after_code or after_code.strip() == "":
            issues.append("Patch result is empty; potential file wipeout prevented.")
            return False, issues

        if after_code == before_code:
            issues.append("Patch produced identical code; no remediation applied.")
            return False, issues

        # 1. Parse check: must be valid Python syntax
        try:
            after_tree = ast.parse(after_code)
        except SyntaxError as e:
            issues.append(f"Syntax error in patched code at line {e.lineno}: {e.msg}")
            return False, issues

        try:
            before_tree = ast.parse(before_code)
        except Exception:
            before_tree = None

        # 2. Scope check: ensure top-level definitions weren't accidentally destroyed
        if before_tree:
            before_defs = {
                n.name for n in ast.walk(before_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            }
            after_defs = {
                n.name for n in ast.walk(after_tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            }
            missing_defs = before_defs - after_defs
            if missing_defs:
                issues.append(f"Patch destroyed existing definitions: {', '.join(missing_defs)}")
                return False, issues

        # 3. Malicious / Dangerous constructs check: ensure patch didn't inject new dangerous calls
        before_calls = set()
        if before_tree:
            for n in ast.walk(before_tree):
                if isinstance(n, ast.Call):
                    if isinstance(n.func, ast.Name):
                        before_calls.add(n.func.id)
                    elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                        before_calls.add(f"{n.func.value.id}.{n.func.attr}")

        for n in ast.walk(after_tree):
            if isinstance(n, ast.Call):
                name = None
                if isinstance(n.func, ast.Name):
                    name = n.func.id
                elif isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                    name = f"{n.func.value.id}.{n.func.attr}"

                if name and name in BANNED_NEW_CALLS and name not in before_calls:
                    issues.append(f"Patch introduced unsafe call `{name}` not present in original.")
                    return False, issues

        return True, []


def validate_patch_safety(before: str, after: str, finding: Finding) -> Tuple[bool, List[str]]:
    """Helper function for safety validation."""
    return PatchSafetyValidator.validate(before, after, finding)

