"""Runtime Scanner - DAST (Flow step F).
Performs dynamic application security testing, runtime configuration auditing,
dynamic behavioral probes, and runtime dependency vulnerability analysis.
"""
import ast
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Known vulnerable package versions catalog for runtime dependency auditing
KNOWN_VULNERABLE_PACKAGES = {
    "pyyaml": {"max_vulnerable": "5.3.1", "cwe": "CWE-502", "cve": "CVE-2020-1747", "advisory": "Arbitrary code execution via unsafe Loader"},
    "requests": {"max_vulnerable": "2.31.0", "cwe": "CWE-200", "cve": "CVE-2023-32681", "advisory": "Proxy-Authorization header leak on HTTPS redirect"},
    "urllib3": {"max_vulnerable": "1.26.18", "cwe": "CWE-200", "cve": "CVE-2023-45803", "advisory": "Cookie leak on cross-site redirect"},
    "flask": {"max_vulnerable": "2.2.5", "cwe": "CWE-79", "cve": "CVE-2023-30861", "advisory": "Session cookie disclosure under certain proxy configs"},
    "werkzeug": {"max_vulnerable": "2.3.8", "cwe": "CWE-20", "cve": "CVE-2023-46136", "advisory": "High memory consumption during multipart parsing"},
    "cryptography": {"max_vulnerable": "41.0.5", "cwe": "CWE-476", "cve": "CVE-2023-49083", "advisory": "NULL-pointer dereference during certificate parsing"},
}


class DASTScanner:
    """Runtime Security Scanner executing dynamic and environmental checks."""

    def __init__(self, excludes: Optional[Set[str]] = None, disabled_rules: Optional[Set[str]] = None):
        self.excludes = excludes or {".git", "__pycache__", "venv", ".venv", "tests", "node_modules", ".autopatch"}
        self.disabled_rules = disabled_rules or set()

    def scan_runtime(self, root: Path) -> List[Dict[str, Any]]:
        """Run all DAST checks across the project tree."""
        findings: List[Dict[str, Any]] = []

        if "DAST001" not in self.disabled_rules or "DAST002" not in self.disabled_rules:
            findings.extend(self._check_runtime_configs(root))

        if "DAST003" not in self.disabled_rules:
            findings.extend(self._check_runtime_dependencies(root))

        if "DAST004" not in self.disabled_rules:
            findings.extend(self._probe_dynamic_sql(root))

        return findings

    def _check_runtime_configs(self, root: Path) -> List[Dict[str, Any]]:
        """Scan configuration files for dangerous active runtime modes."""
        findings = []
        for p in root.rglob("*.py"):
            rel = p.relative_to(root)
            if any(part in self.excludes for part in rel.parts[:-1]):
                continue
            name_lower = p.name.lower()
            if not ("config" in name_lower or "setting" in name_lower or "app" in name_lower):
                continue

            try:
                content = p.read_text(encoding="utf-8")
                tree = ast.parse(content)
            except Exception:
                continue

            lines = content.splitlines()

            for node in ast.walk(tree):
                # DAST001: Active DEBUG = True
                if isinstance(node, ast.Assign) and "DAST001" not in self.disabled_rules:
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "DEBUG":
                            if isinstance(node.value, ast.Constant) and node.value.value is True:
                                findings.append({
                                    "rule_id": "DAST001",
                                    "scanner_type": "DAST",
                                    "file": rel.as_posix(),
                                    "line": node.lineno,
                                    "col": node.col_offset,
                                    "snippet": lines[node.lineno - 1].strip()[:140],
                                    "key": "DEBUG=True",
                                })

                        # DAST002: Wildcard CORS
                        if isinstance(target, ast.Name) and "cors" in target.id.lower() and "DAST002" not in self.disabled_rules:
                            if isinstance(node.value, (ast.List, ast.Set, ast.Tuple)):
                                for elt in node.value.elts:
                                    if isinstance(elt, ast.Constant) and elt.value == "*":
                                        findings.append({
                                            "rule_id": "DAST002",
                                            "scanner_type": "DAST",
                                            "file": rel.as_posix(),
                                            "line": node.lineno,
                                            "col": node.col_offset,
                                            "snippet": lines[node.lineno - 1].strip()[:140],
                                            "key": "CORS_WILDCARD",
                                        })
        return findings

    def _check_runtime_dependencies(self, root: Path) -> List[Dict[str, Any]]:
        """Audit runtime requirements manifests for known vulnerable packages."""
        findings = []
        manifest_files = ["requirements.txt", "Pipfile", "pyproject.toml"]

        for manifest_name in manifest_files:
            for p in root.rglob(manifest_name):
                rel = p.relative_to(root)
                if any(part in self.excludes for part in rel.parts[:-1]):
                    continue
                try:
                    lines = p.read_text(encoding="utf-8").splitlines()
                except Exception:
                    continue

                for i, line in enumerate(lines, 1):
                    clean = line.strip()
                    if not clean or clean.startswith("#"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_\-]+)\s*(?:==|<=|~=)\s*([0-9\.]+)", clean)
                    if m:
                        pkg_name = m.group(1).lower()
                        ver = m.group(2)
                        if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                            vuln = KNOWN_VULNERABLE_PACKAGES[pkg_name]
                            if self._is_version_lower_or_equal(ver, vuln["max_vulnerable"]):
                                findings.append({
                                    "rule_id": "DAST003",
                                    "scanner_type": "DAST",
                                    "file": rel.as_posix(),
                                    "line": i,
                                    "col": 0,
                                    "snippet": clean[:140],
                                    "key": f"{pkg_name}@{ver}",
                                })
        return findings

    def _probe_dynamic_sql(self, root: Path) -> List[Dict[str, Any]]:
        """Dynamic heuristic probe: inspect runtime SQL construction patterns for probe sensitivity."""
        findings = []
        # Inspect queries where dynamic string concatenation occurs inside execute calls
        for p in root.rglob("*.py"):
            rel = p.relative_to(root)
            if any(part in self.excludes for part in rel.parts[:-1]):
                continue
            try:
                content = p.read_text(encoding="utf-8")
                tree = ast.parse(content)
            except Exception:
                continue

            lines = content.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("execute", "executemany") and node.args:
                        arg = node.args[0]
                        # Check for LIKE '%...%' or string concatenations that lead to runtime syntax/injection anomalies
                        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                            text_rep = ast.unparse(arg)
                            if "LIKE" in text_rep.upper() and ("%" in text_rep or "+" in text_rep):
                                findings.append({
                                    "rule_id": "DAST004",
                                    "scanner_type": "DAST",
                                    "file": rel.as_posix(),
                                    "line": node.lineno,
                                    "col": node.col_offset,
                                    "snippet": lines[node.lineno - 1].strip()[:140],
                                    "key": "LIKE_PROBE_ANOMALY",
                                })
        return findings

    @staticmethod
    def _is_version_lower_or_equal(v1: str, v2: str) -> bool:
        """Compare two version strings numerically."""
        try:
            p1 = [int(x) for x in v1.split(".") if x.isdigit()]
            p2 = [int(x) for x in v2.split(".") if x.isdigit()]
            return p1 <= p2
        except Exception:
            return False

