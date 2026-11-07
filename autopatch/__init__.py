"""AutoPatch AI: detect, classify, repair, and verify Python security findings automatically."""
from .dast import DASTScanner
from .detector import VulnerabilityDetector
from .findings import Finding, make_fingerprint
from .orchestrator import NotAuthorized, run
from .rag_engine import RAGExtension
from .remediation import RemediationEngine
from .risk import RiskAnalyzer
from .safety import validate_patch_safety
from .sast import SASTScanner
from .validator import validate_project
from .vuln_db import get_rule

__version__ = "2.0.0"

__all__ = [
    "run",
    "NotAuthorized",
    "SASTScanner",
    "DASTScanner",
    "VulnerabilityDetector",
    "RiskAnalyzer",
    "RemediationEngine",
    "RAGExtension",
    "validate_patch_safety",
    "validate_project",
    "Finding",
    "make_fingerprint",
    "get_rule",
]
