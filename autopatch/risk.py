"""Finding Classification & Risk Analysis module (Flow step H).
Classifies findings, assigns CWE and OWASP categories,
and calculates quantitative risk scores and confidence levels.
"""
from typing import List

from .findings import Finding
from .vuln_db import SEVERITY_ORDER, VULN_DATABASE, get_rule

CONFIDENCE_BY_RULE = {
    "AP001": 98,  # AST query execution with dynamic formatting
    "AP002": 99,  # Direct eval/exec AST call
    "AP003": 97,  # Exact hashlib MD5/SHA1 call
    "AP004": 95,  # yaml.load without Loader keyword
    "AP005": 96,  # verify=False keyword argument
    "AP006": 90,  # Regex pattern for hardcoded secret
    "AP007": 94,  # os.system / subprocess shell=True
    "DAST001": 95, # DEBUG=True in runtime config
    "DAST002": 93, # CORS wildcard
    "DAST003": 98, # Package version comparison
    "DAST004": 91, # Dynamic runtime SQL probe anomaly
}


class RiskAnalyzer:
    """Analyzes and quantifies risk for security findings."""

    @classmethod
    def analyze(cls, findings: List[Finding]) -> List[Finding]:
        for f in findings:
            meta = get_rule(f.rule_id)
            f.title = meta["title"]
            f.severity = meta["severity"]
            f.category = meta["category"]
            f.cwe = meta["cwe"]
            f.owasp = meta.get("owasp", "")
            f.cvss_base = meta.get("cvss_base", 5.0)
            f.fixable = meta.get("fixable", False)
            f.confidence = CONFIDENCE_BY_RULE.get(f.rule_id, 90)
            f.explanation = meta.get("description", "")
            f.remediation_guide = meta.get("remediation_guide", "")

            # Calculate composite risk score: CVSS base modulated slightly by confidence
            # e.g., 9.8 base with 99% confidence -> 9.8; 5.0 base with 90% confidence -> 4.8
            f.risk_score = round(f.cvss_base * (0.8 + 0.2 * (f.confidence / 100.0)), 1)

        # Sort by severity order (critical -> high -> medium -> low), then file and line
        return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))


def classify(findings: List[Finding]) -> List[Finding]:
    """Backward compatibility helper for classification and risk analysis."""
    return RiskAnalyzer.analyze(findings)

