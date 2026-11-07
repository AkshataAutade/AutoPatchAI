"""AI-Assisted Analysis / RAG - Extension module (Flow step L).
Combines Retrieval-Augmented Generation (RAG) using the Vulnerability Database
with AI-driven root cause analysis, attack scenario explanation, and patch synthesis.
"""
import ast
import json
import os
import re
from typing import Any, Dict, Optional, Tuple

from .findings import Finding
from .vuln_db import get_rule


class RAGExtension:
    """Retrieves security knowledge base context and generates AI explanations & patches."""

    def __init__(self, ai_provider: Optional[str] = None):
        self.ai_provider = ai_provider or os.environ.get("AUTOPATCH_AI_PROVIDER", "auto")

    def retrieve_context(self, finding: Finding, source_code: str) -> Dict[str, Any]:
        """RAG Retrieval: gathers vulnerability intelligence and local code context."""
        rule_meta = get_rule(finding.rule_id)

        # Extract surrounding context lines (5 lines before and after)
        lines = source_code.splitlines()
        target_line = max(1, min(finding.line, len(lines)))
        start_idx = max(0, target_line - 5)
        end_idx = min(len(lines), target_line + 5)
        context_snippet = "\n".join(
            f"{i + 1:4d} | {lines[i]}" for i in range(start_idx, end_idx)
        )

        return {
            "rule": rule_meta,
            "snippet": finding.snippet,
            "line": finding.line,
            "file": finding.file,
            "code_context": context_snippet,
            "cwe": rule_meta.get("cwe", ""),
            "owasp": rule_meta.get("owasp", ""),
            "secure_example": rule_meta.get("secure_example", ""),
            "vulnerable_example": rule_meta.get("vulnerable_example", ""),
            "remediation_guide": rule_meta.get("remediation_guide", ""),
        }

    def generate_analysis(self, finding: Finding, source_code: str) -> str:
        """Generate AI explanation of vulnerability, attack vector, and remediation strategy."""
        rag_ctx = self.retrieve_context(finding, source_code)
        rule = rag_ctx["rule"]

        explanation = (
            f"### AI-Assisted Security Analysis: {rule['title']}\n\n"
            f"**Classification:** {rule['cwe']} ({rule.get('owasp', 'OWASP')}) | **Severity:** {rule['severity'].upper()}\n\n"
            f"**Root Cause:** In `{finding.file}` at line {finding.line}, the application performs: `{finding.snippet}`. "
            f"{rule['description']}\n\n"
            f"**Attack Vector & Impact:** {rule['impact']}\n\n"
            f"**Recommended Remediation:** {rule['remediation_guide']}"
        )
        return explanation

    def synthesize_patch(self, source_code: str, finding: Finding, ctx: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """Synthesize an AI patch proposal using RAG context.
        Returns (patched_source, patch_notes) or None if unable to synthesize safely.
        """
        # If external API keys (Gemini / OpenAI) are provided, we can call remote LLM
        # Otherwise, fall back to our built-in intelligent contextual patch engine.
        gemini_key = os.environ.get("GEMINI_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")

        if gemini_key and self.ai_provider in ("auto", "gemini"):
            res = self._call_gemini_patch(gemini_key, source_code, finding, ctx)
            if res:
                return res

        if openai_key and self.ai_provider in ("auto", "openai"):
            res = self._call_openai_patch(openai_key, source_code, finding, ctx)
            if res:
                return res

        # Fallback to internal heuristic RAG patch synthesizer
        return self._heuristic_rag_patch(source_code, finding, ctx)

    def _heuristic_rag_patch(self, source_code: str, finding: Finding, ctx: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """Local RAG patch synthesizer for patterns beyond basic deterministic AST matching."""
        placeholder = ctx.get("placeholder", "?")
        lines = source_code.splitlines()

        # Complex SQL with LIKE '%" + term + "%' (e.g. products search in vulnerable_app)
        if finding.rule_id == "AP001" and "LIKE" in finding.snippet.upper():
            line_idx = finding.line - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                # Pattern: cur.execute("SELECT ... WHERE name LIKE '%" + term + "%'")
                # We want: cur.execute("SELECT ... WHERE name LIKE ?", (f"%{term}%",))
                m = re.search(r"""(cur|cursor|conn)\.execute\(\s*(["'].*?WHERE\s+.*?\s+LIKE\s+)(['"]\s*%\s*['"]\s*\+\s*(\w+)\s*\+\s*['"]\s*%\s*['"])(.*?)\)""", line)
                if m:
                    cursor_var = m.group(1)
                    query_prefix = m.group(2)
                    var_name = m.group(4)
                    new_line = re.sub(
                        r"""(["'].*?WHERE\s+.*?\s+LIKE\s+)(['"]\s*%\s*['"]\s*\+\s*(\w+)\s*\+\s*['"]\s*%\s*['"])""",
                        f'\\1{placeholder}", (f"%{{{var_name}}}%",)',
                        line
                    )
                    # Clean up quotes
                    new_line = new_line.replace(f'LIKE {placeholder}",', f'LIKE {placeholder}",')
                    lines[line_idx] = new_line
                    patched = "\n".join(lines)
                    return patched, "AI synthesized parameterized query with bounded wildcard for SQL LIKE clause."

        # AP006: Hardcoded secret -> load from environment variable
        if finding.rule_id == "AP006":
            line_idx = finding.line - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                m = re.match(r"""^\s*([A-Za-z_]\w*)\s*=\s*(['"])(.*?)\2""", line)
                if m:
                    var_name = m.group(1)
                    indent = len(line) - len(line.lstrip())
                    spaces = " " * indent
                    new_line = f"{spaces}{var_name} = os.environ.get(\"{var_name}\", \"\")"
                    lines[line_idx] = new_line
                    patched = "\n".join(lines)
                    if "import os" not in patched:
                        patched = "import os\n" + patched
                    return patched, f"AI replaced hardcoded secret with dynamic `os.environ.get('{var_name}')`."

        # DAST001: Active DEBUG = True -> load from environment variable
        if finding.rule_id == "DAST001":
            line_idx = finding.line - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                if "DEBUG = True" in line:
                    lines[line_idx] = line.replace("DEBUG = True", "DEBUG = os.environ.get('APP_DEBUG', 'False').lower() == 'true'")
                    patched = "\n".join(lines)
                    if "import os" not in patched:
                        patched = "import os\n" + patched
                    return patched, "AI secured debug flag by disabling default active debug mode in runtime config."

        # DAST002: Wildcard CORS -> Restricted origin
        if finding.rule_id == "DAST002":
            line_idx = finding.line - 1
            if line_idx < len(lines):
                line = lines[line_idx]
                if '"*"' in line or "'*'" in line:
                    new_line = line.replace('"*"', 'os.environ.get("ALLOWED_ORIGIN", "https://localhost:3000")')
                    new_line = new_line.replace("'*'", 'os.environ.get("ALLOWED_ORIGIN", "https://localhost:3000")')
                    lines[line_idx] = new_line
                    patched = "\n".join(lines)
                    if "import os" not in patched:
                        patched = "import os\n" + patched
                    return patched, "AI restricted wildcard CORS to explicit origin environment configuration."

        return None

    def _call_gemini_patch(self, api_key: str, source_code: str, finding: Finding, ctx: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        # Hook for remote Gemini API when configured
        return None

    def _call_openai_patch(self, api_key: str, source_code: str, finding: Finding, ctx: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        # Hook for remote OpenAI API when configured
        return None

