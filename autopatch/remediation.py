"""Remediation Engine & Patch Generation module (Flow steps J, K, L, M).
Dispatches findings to deterministic Security Rules & Patch Templates (K)
or AI-Assisted Analysis / RAG - Extension (L) to produce patch candidates (M).
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .findings import Finding
from .rag_engine import RAGExtension
from .repair import FIXERS


@dataclass
class PatchCandidate:
    finding: Finding
    before_code: str
    after_code: Optional[str]
    strategy: str  # "rule_template" | "ai_assisted_rag" | "manual_review"
    notes: str
    diff: Optional[str] = None


class RemediationEngine:
    """Coordinates patch generation via deterministic rules and AI/RAG."""

    def __init__(self, enable_ai: bool = True):
        self.rag = RAGExtension() if enable_ai else None

    def remediate(self, finding: Finding, source_code: str, ctx: Dict[str, Any]) -> PatchCandidate:
        """Attempt to remediate a finding using templates first, falling back to AI/RAG."""
        rule_id = finding.rule_id
        fixer = FIXERS.get(rule_id)

        # 1. First attempt: Security Rules & Patch Templates (K)
        if fixer and finding.fixable:
            try:
                after = fixer(source_code, finding, ctx)
                if after and after != source_code:
                    return PatchCandidate(
                        finding=finding,
                        before_code=source_code,
                        after_code=after,
                        strategy="rule_template",
                        notes=f"Generated via deterministic security rule template for {rule_id}.",
                    )
            except Exception as e:
                # Log or handle unexpected fixer failure
                pass

        # 2. Second attempt: AI-Assisted Analysis / RAG - Extension (L)
        if self.rag:
            try:
                ai_patch = self.rag.synthesize_patch(source_code, finding, ctx)
                if ai_patch:
                    after, notes = ai_patch
                    if after and after != source_code:
                        return PatchCandidate(
                            finding=finding,
                            before_code=source_code,
                            after_code=after,
                            strategy="ai_assisted_rag",
                            notes=notes,
                        )
            except Exception:
                pass

        # 3. If no automated fix is available -> Manual Review
        return PatchCandidate(
            finding=finding,
            before_code=source_code,
            after_code=None,
            strategy="manual_review",
            notes="No automatic rule template or AI patch available for this code pattern.",
        )

