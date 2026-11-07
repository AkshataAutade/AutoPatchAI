"""Rule catalogue: severity and classification for every finding type."""

RULES = {
    "AP001": dict(title="SQL injection via dynamically built query", severity="high",
                  category="Injection", cwe="CWE-89", fixable=True),
    "AP002": dict(title="eval() on dynamic input", severity="critical",
                  category="Code injection", cwe="CWE-95", fixable=True),
    "AP003": dict(title="Weak hash algorithm (MD5 / SHA-1)", severity="medium",
                  category="Cryptography", cwe="CWE-327", fixable=True),
    "AP004": dict(title="yaml.load without a safe loader", severity="high",
                  category="Deserialization", cwe="CWE-502", fixable=True),
    "AP005": dict(title="TLS certificate verification disabled", severity="high",
                  category="Transport security", cwe="CWE-295", fixable=True),
    "AP006": dict(title="Hardcoded credential", severity="high",
                  category="Secrets", cwe="CWE-798", fixable=False),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
