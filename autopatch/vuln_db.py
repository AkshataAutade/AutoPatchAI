"""Vulnerability Database & Knowledge Base for AutoPatch AI.
Contains security rules, CWE/OWASP mappings, severity baselines,
remediation guidelines, and knowledge context for RAG.
"""

VULN_DATABASE = {
    "AP001": {
        "rule_id": "AP001",
        "title": "SQL injection via dynamically built query",
        "severity": "high",
        "category": "Injection",
        "cwe": "CWE-89",
        "cwe_title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "owasp": "A03:2021-Injection",
        "cvss_base": 8.8,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "Untrusted input is concatenated, formatted, or interpolated directly into an SQL "
            "statement executed by a database cursor. An attacker can manipulate the query "
            "structure to bypass authentication, view unauthorized data, or modify database records."
        ),
        "impact": "Data breach, data loss, unauthorized administrative access, privilege escalation.",
        "remediation_guide": (
            "Use parameterized queries with placeholder binding (e.g., '?' for SQLite or '%s' "
            "for PostgreSQL/MySQL) and pass variables as a separate parameter sequence. "
            "Never construct SQL commands by joining or formatting strings with user input."
        ),
        "vulnerable_example": "cur.execute(f\"SELECT * FROM users WHERE username = '{username}'\")",
        "secure_example": "cur.execute(\"SELECT * FROM users WHERE username = ?\", (username,))",
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    },
    "AP002": {
        "rule_id": "AP002",
        "title": "eval() on dynamic input",
        "severity": "critical",
        "category": "Code injection",
        "cwe": "CWE-95",
        "cwe_title": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "owasp": "A03:2021-Injection",
        "cvss_base": 9.8,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "The built-in `eval()` function is invoked with dynamic or untrusted input. "
            "In Python, `eval()` executes arbitrary Python code in the current runtime context, "
            "enabling remote code execution (RCE) and full host compromise."
        ),
        "impact": "Remote code execution (RCE), complete system takeover, arbitrary file access.",
        "remediation_guide": (
            "Replace `eval()` with `ast.literal_eval()` when parsing Python literal expressions "
            "(strings, numbers, tuples, lists, dicts, booleans, and None), or use `json.loads()` "
            "for structured data."
        ),
        "vulnerable_example": "result = eval(user_input)",
        "secure_example": "import ast\nresult = ast.literal_eval(user_input)",
        "references": [
            "https://cwe.mitre.org/data/definitions/95.html",
            "https://docs.python.org/3/library/ast.html#ast.literal_eval",
        ],
    },
    "AP003": {
        "rule_id": "AP003",
        "title": "Weak cryptographic hash algorithm (MD5 / SHA-1)",
        "severity": "medium",
        "category": "Cryptography",
        "cwe": "CWE-327",
        "cwe_title": "Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "A02:2021-Cryptographic Failures",
        "cvss_base": 5.3,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "The code uses MD5 or SHA-1 for hashing. Both algorithms have known collision attacks "
            "and are cryptographically broken for digital signatures, integrity verification, "
            "and credential storage."
        ),
        "impact": "Hash collision attacks, credential cracking, signature forgery.",
        "remediation_guide": (
            "Use secure collision-resistant hash algorithms such as SHA-256 or SHA-512 from "
            "`hashlib`. For password hashing, use dedicated slow algorithms such as Argon2, bcrypt, or scrypt."
        ),
        "vulnerable_example": "hashlib.md5(data.encode()).hexdigest()",
        "secure_example": "hashlib.sha256(data.encode()).hexdigest()",
        "references": [
            "https://cwe.mitre.org/data/definitions/327.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    },
    "AP004": {
        "rule_id": "AP004",
        "title": "yaml.load without a safe loader",
        "severity": "high",
        "category": "Deserialization",
        "cwe": "CWE-502",
        "cwe_title": "Deserialization of Untrusted Data",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "cvss_base": 8.1,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "Calling `yaml.load()` without an explicit safe loader can deserialize arbitrary Python "
            "objects and instantiate classes, allowing attackers to achieve remote code execution "
            "through crafted YAML payloads."
        ),
        "impact": "Arbitrary object instantiation, remote code execution (RCE).",
        "remediation_guide": (
            "Replace `yaml.load(payload)` with `yaml.safe_load(payload)` or specify `Loader=yaml.SafeLoader`."
        ),
        "vulnerable_example": "data = yaml.load(user_content)",
        "secure_example": "data = yaml.safe_load(user_content)",
        "references": [
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ],
    },
    "AP005": {
        "rule_id": "AP005",
        "title": "TLS certificate verification disabled",
        "severity": "high",
        "category": "Transport security",
        "cwe": "CWE-295",
        "cwe_title": "Improper Certificate Validation",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "cvss_base": 7.4,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "Disabling TLS/SSL certificate validation (`verify=False`) makes outbound HTTPS connections "
            "susceptible to adversary-in-the-middle (MitM) attacks. An intercepting party can read or modify "
            "traffic in transit without detection."
        ),
        "impact": "Eavesdropping, credential interception, data tampering in transit.",
        "remediation_guide": (
            "Enable TLS certificate validation by setting `verify=True` or providing a valid CA bundle path."
        ),
        "vulnerable_example": "requests.get(url, verify=False)",
        "secure_example": "requests.get(url, verify=True)",
        "references": [
            "https://cwe.mitre.org/data/definitions/295.html",
        ],
    },
    "AP006": {
        "rule_id": "AP006",
        "title": "Hardcoded credential",
        "severity": "high",
        "category": "Secrets",
        "cwe": "CWE-798",
        "cwe_title": "Use of Hard-coded Credentials",
        "owasp": "A07:2021-Identification and Authentication Failures",
        "cvss_base": 7.5,
        "fixable": False,
        "scanner_type": "SAST",
        "description": (
            "Sensitive credentials such as passwords, API keys, or tokens are hardcoded into "
            "source files. Hardcoded secrets are easily extracted via source repositories, "
            "build artifacts, or application logs."
        ),
        "impact": "Unauthorized system access, compromised third-party accounts, privilege escalation.",
        "remediation_guide": (
            "Rotate the exposed secret immediately. Extract credentials into environment variables "
            "(e.g., using `os.environ.get(...)`) or a dedicated secret management vault."
        ),
        "vulnerable_example": "API_KEY = \"AKIA1234567890EXAMPLE\"",
        "secure_example": "import os\nAPI_KEY = os.environ.get(\"API_KEY\")",
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
    },
    "AP007": {
        "rule_id": "AP007",
        "title": "Command injection via shell execution",
        "severity": "critical",
        "category": "Command injection",
        "cwe": "CWE-78",
        "cwe_title": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "owasp": "A03:2021-Injection",
        "cvss_base": 9.8,
        "fixable": True,
        "scanner_type": "SAST",
        "description": (
            "Invoking shell commands with dynamic input through `os.system()` or `subprocess` with `shell=True` "
            "allows attackers to inject arbitrary operating system commands using command separators (;, &, |)."
        ),
        "impact": "Arbitrary OS command execution, host compromise, data extraction.",
        "remediation_guide": (
            "Use `subprocess.run()` with `shell=False` and pass arguments as a list of strings rather than a concatenated command string."
        ),
        "vulnerable_example": "os.system('ping ' + user_host)",
        "secure_example": "import subprocess\nsubprocess.run(['ping', '-c', '1', user_host], check=True)",
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    "DAST001": {
        "rule_id": "DAST001",
        "title": "Insecure runtime debug mode active",
        "severity": "high",
        "category": "Security misconfiguration",
        "cwe": "CWE-489",
        "cwe_title": "Active Debug Code",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss_base": 7.5,
        "fixable": True,
        "scanner_type": "DAST",
        "description": (
            "Application runtime configuration has `DEBUG = True` enabled. Active debug modes in runtime "
            "often expose interactive tracebacks, internal configuration, secret keys, and interactive debug consoles."
        ),
        "impact": "Information disclosure, credential leakage, possible remote code execution via debug consoles.",
        "remediation_guide": (
            "Set `DEBUG = False` in runtime configuration or load debug setting dynamically from an environment variable with a safe default."
        ),
        "vulnerable_example": "DEBUG = True",
        "secure_example": "DEBUG = os.environ.get('APP_DEBUG', 'False').lower() == 'true'",
        "references": [
            "https://cwe.mitre.org/data/definitions/489.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "DAST002": {
        "rule_id": "DAST002",
        "title": "Permissive runtime wildcard CORS configuration",
        "severity": "medium",
        "category": "Security misconfiguration",
        "cwe": "CWE-942",
        "cwe_title": "Permissive Cross-domain Policy with Untrusted Domains",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss_base": 5.4,
        "fixable": True,
        "scanner_type": "DAST",
        "description": (
            "Cross-Origin Resource Sharing (CORS) is configured to allow all origins ('*'). "
            "This permits untrusted external websites to issue cross-origin requests and read sensitive responses."
        ),
        "impact": "Cross-origin data exposure, session riding, unauthorized data extraction.",
        "remediation_guide": (
            "Restrict CORS origins to explicit trusted domain names instead of using a wildcard ('*')."
        ),
        "vulnerable_example": "CORS_ORIGINS = ['*']",
        "secure_example": "CORS_ORIGINS = ['https://trusted.example.com']",
        "references": [
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    },
    "DAST003": {
        "rule_id": "DAST003",
        "title": "Vulnerable runtime dependency detected",
        "severity": "high",
        "category": "Vulnerable dependency",
        "cwe": "CWE-1395",
        "cwe_title": "Dependency on Vulnerable Third-Party Component",
        "owasp": "A06:2021-Vulnerable and Outdated Components",
        "cvss_base": 7.5,
        "fixable": False,
        "scanner_type": "DAST",
        "description": (
            "The runtime manifest or installed packages reference a third-party dependency with known public "
            "security vulnerabilities."
        ),
        "impact": "Exploitation of known vulnerabilities in third-party libraries.",
        "remediation_guide": (
            "Upgrade the vulnerable package to a patched version specified in security advisories."
        ),
        "vulnerable_example": "pyyaml==5.1",
        "secure_example": "pyyaml>=6.0.1",
        "references": [
            "https://cwe.mitre.org/data/definitions/1395.html",
        ],
    },
    "DAST004": {
        "rule_id": "DAST004",
        "title": "Runtime dynamic SQL error / injection probe anomaly",
        "severity": "high",
        "category": "Injection",
        "cwe": "CWE-89",
        "cwe_title": "Improper Neutralization of Special Elements used in an SQL Command",
        "owasp": "A03:2021-Injection",
        "cvss_base": 8.6,
        "fixable": True,
        "scanner_type": "DAST",
        "description": (
            "Dynamic runtime probe executed against query handlers detected unhandled SQL syntax errors "
            "or data manipulation when probe metacharacters (' OR '1'='1) were injected into parameters."
        ),
        "impact": "SQL query manipulation, authentication bypass, data exposure.",
        "remediation_guide": "Enforce strict parameterized queries across all database access layers.",
        "vulnerable_example": "cur.execute(\"SELECT ... WHERE \" + param)",
        "secure_example": "cur.execute(\"SELECT ... WHERE field = ?\", (param,))",
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
}

RULES_LOOKUP = {k: {
    "title": v["title"],
    "severity": v["severity"],
    "category": v["category"],
    "cwe": v["cwe"],
    "fixable": v["fixable"],
    "scanner_type": v.get("scanner_type", "SAST"),
} for k, v in VULN_DATABASE.items()}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def get_rule(rule_id: str) -> dict:
    return VULN_DATABASE.get(rule_id, {
        "rule_id": rule_id,
        "title": f"Security Finding {rule_id}",
        "severity": "medium",
        "category": "General Security",
        "cwe": "CWE-699",
        "cwe_title": "Software Development Weakness",
        "owasp": "A00:2021-General",
        "cvss_base": 5.0,
        "fixable": False,
        "scanner_type": "SAST",
        "description": "Security finding detected during analysis.",
        "impact": "Potential security risk.",
        "remediation_guide": "Review code against secure programming standards.",
        "vulnerable_example": "",
        "secure_example": "",
        "references": [],
    })

