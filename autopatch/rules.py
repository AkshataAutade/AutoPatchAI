"""Rule catalogue: severity and classification for every finding type."""
from .vuln_db import RULES_LOOKUP, SEVERITY_ORDER, VULN_DATABASE, get_rule

RULES = RULES_LOOKUP

__all__ = ["RULES", "SEVERITY_ORDER", "VULN_DATABASE", "get_rule"]
