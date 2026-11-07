"""Comprehensive test suite for AutoPatch AI flow.
Validates each node of the architectural flowchart:
A -> B -> C -> D -> E & F -> G -> H & I -> J -> K & L -> M -> N -> O -> P -> Q -> R -> S/T -> U -> V, W, X.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from autopatch.dast import DASTScanner
from autopatch.detector import VulnerabilityDetector
from autopatch.findings import Finding, make_fingerprint
from autopatch.orchestrator import run
from autopatch.rag_engine import RAGExtension
from autopatch.remediation import RemediationEngine
from autopatch.risk import RiskAnalyzer
from autopatch.safety import validate_patch_safety
from autopatch.sast import SASTScanner
from autopatch.validator import NotAuthorized, validate_project
from autopatch.vuln_db import get_rule


class AutoPatchFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="autopatch_test_")
        self.root = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _setup_project(self, authorized=True, files=None):
        proj = self.root / "proj"
        proj.mkdir()
        if authorized:
            (proj / ".autopatch.json").write_text(json.dumps({"authorized": True}))
        if files:
            for rel, content in files.items():
                p = proj / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
        return proj

    def test_flow_c_unauthorized_rejection(self):
        """Step C: Non-authorized projects must be rejected before any scan or change."""
        proj = self.root / "unauthorized_proj"
        proj.mkdir()
        (proj / "app.py").write_text("print('hello')")

        res = validate_project(proj)
        self.assertFalse(res.authorized)
        self.assertFalse(res.valid)
        self.assertTrue(any("not authorized" in e.lower() for e in res.errors))

        out = self.root / "out"
        with self.assertRaises(NotAuthorized):
            run(proj, out)

    def test_flow_c_authorized_validation(self):
        """Step C: Authorized projects are successfully validated."""
        proj = self._setup_project(authorized=True, files={"main.py": "x = 1"})
        res = validate_project(proj)
        self.assertTrue(res.authorized)
        self.assertTrue(res.valid)
        self.assertEqual(res.python_files_count, 1)

    def test_flow_e_sast_scanner(self):
        """Step E: SAST scanner detects static AST security patterns."""
        scanner = SASTScanner()
        code = "import hashlib\ndef foo(x):\n    cur.execute(f'SELECT * FROM u WHERE id={x}')\n    return hashlib.md5(b'x')\n"
        findings = scanner.scan_source(code, "test.py")
        self.assertIsNotNone(findings)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("AP001", rule_ids)  # SQLi
        self.assertIn("AP003", rule_ids)  # Weak hash

    def test_flow_f_dast_scanner(self):
        """Step F: DAST scanner detects runtime configuration & dependency risks."""
        proj = self._setup_project(
            authorized=True,
            files={
                "config.py": "DEBUG = True\nCORS_ORIGINS = ['*']\n",
                "requirements.txt": "pyyaml==5.1\nrequests==2.25.0\n",
            }
        )
        dast = DASTScanner()
        findings = dast.scan_runtime(proj)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("DAST001", rule_ids)  # Active DEBUG
        self.assertIn("DAST002", rule_ids)  # Wildcard CORS
        self.assertIn("DAST003", rule_ids)  # Vulnerable dependency pyyaml

    def test_flow_g_vulnerability_detection_aggregation(self):
        """Step G: Vulnerability Detection aggregates and deduplicates SAST and DAST."""
        sast_raw = [{"rule_id": "AP001", "file": "app.py", "line": 10, "col": 4, "snippet": "cur.execute()", "key": "k1"}]
        dast_raw = [{"rule_id": "DAST001", "file": "config.py", "line": 2, "col": 0, "snippet": "DEBUG=True", "key": "k2"}]
        combined = VulnerabilityDetector.detect(sast_raw, dast_raw)
        self.assertEqual(len(combined), 2)
        scanners = {f.scanner_type for f in combined}
        self.assertEqual(scanners, {"SAST", "DAST"})

    def test_flow_h_risk_analysis(self):
        """Step H: Risk analysis computes scores and classification."""
        finding = Finding(
            rule_id="AP002",
            file="app.py",
            line=5,
            col=0,
            snippet="eval(x)",
            fingerprint="abc123",
            scanner_type="SAST",
        )
        classified = RiskAnalyzer.analyze([finding])
        f = classified[0]
        self.assertEqual(f.severity, "critical")
        self.assertGreaterEqual(f.risk_score, 9.0)
        self.assertEqual(f.cwe, "CWE-95")

    def test_flow_j_k_l_m_remediation_and_rag(self):
        """Steps J, K, L, M: Remediation engine uses rules and RAG to generate patches."""
        import ast
        engine = RemediationEngine(enable_ai=True)
        source = "def calc(payload):\n    return eval(payload)\n"
        tree = ast.parse(source)
        call_node = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
        fp = make_fingerprint("AP002", "utils.py", ast.dump(call_node))

        finding = Finding(
            rule_id="AP002",
            file="utils.py",
            line=call_node.lineno,
            col=call_node.col_offset,
            snippet="return eval(payload)",
            fingerprint=fp,
            fixable=True,
        )
        patch = engine.remediate(finding, source, ctx={"placeholder": "?"})
        self.assertIsNotNone(patch.after_code)
        self.assertIn("ast.literal_eval", patch.after_code)
        self.assertEqual(patch.strategy, "rule_template")

    def test_flow_n_patch_safety_validation(self):
        """Step N: Safety validator blocks invalid syntax and unsafe modifications."""
        finding = Finding(rule_id="AP001", file="db.py", line=1, col=0, snippet="", fingerprint="f1")
        # Valid patch
        safe, issues = validate_patch_safety("x = 1\n", "x = 2\n", finding)
        self.assertTrue(safe)
        self.assertEqual(issues, [])

        # Syntax error
        safe, issues = validate_patch_safety("x = 1\n", "x = def broken(\n", finding)
        self.assertFalse(safe)
        self.assertTrue(any("syntax error" in i.lower() for i in issues))

        # Empty result
        safe, issues = validate_patch_safety("x = 1\n", "", finding)
        self.assertFalse(safe)

        # Introduction of dangerous call
        safe, issues = validate_patch_safety("x = 1\n", "x = 1\nos.system('rm -rf /')\n", finding)
        self.assertFalse(safe)
        self.assertTrue(any("unsafe call" in i.lower() for i in issues))

    def test_flow_end_to_end_orchestrator(self):
        """Steps A through X: Complete pipeline run on vulnerable_app."""
        target = Path("examples/vulnerable_app").resolve()
        out = self.root / "autopatch-out"

        rep = run(target, out, apply=False)

        self.assertTrue(rep["authorized"])
        self.assertFalse(rep["clean_scan"])
        self.assertTrue(rep["baseline_tests_ok"])

        counts = rep["counts"]
        self.assertGreaterEqual(counts["found"], 7)
        self.assertGreater(counts["accepted"], 0)
        self.assertGreater(counts["rejected"], 0)

        # Check reports exist
        self.assertTrue((out / "report.json").is_file())
        self.assertTrue((out / "report.md").is_file())
        self.assertTrue((out / "patches").is_dir())
        self.assertTrue((out / "rejected").is_dir())
        self.assertTrue((out / "originals").is_dir())

        # Check flow execution map contains steps
        flow = rep["flow_execution"]
        self.assertIn("A_user_input", flow)
        self.assertIn("B_input_project", flow)
        self.assertIn("C_authorization_validation", flow)
        self.assertIn("D_orchestrator_init", flow)
        self.assertIn("E_sast_scanner", flow)
        self.assertIn("F_dast_scanner", flow)
        self.assertIn("G_vulnerability_detection", flow)
        self.assertIn("H_risk_analysis", flow)
        self.assertIn("I_vuln_database", flow)
        self.assertIn("J_remediation_engine", flow)
        self.assertIn("K_security_rules", flow)
        self.assertIn("L_ai_rag_extension", flow)
        self.assertIn("M_patch_generation", flow)
        self.assertIn("N_patch_safety_validation", flow)
        self.assertIn("O_apply_to_project_copy", flow)
        self.assertIn("P_automated_testing", flow)
        self.assertIn("Q_rescan_verification", flow)
        self.assertIn("R_decision", flow)
        self.assertIn("S_accepted", flow)
        self.assertIn("T_rejected", flow)
        self.assertIn("U_final_reports", flow)
        self.assertIn("V_json_report", flow)
        self.assertIn("W_markdown_report", flow)
        self.assertIn("X_developer_review", flow)

    def test_flow_u_v_w_reports(self):
        """Steps U, V, W: Validate JSON and Markdown reports content."""
        target = Path("examples/vulnerable_app").resolve()
        out = self.root / "rep_out"
        rep = run(target, out)
        json_rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        md_rep = (out / "report.md").read_text(encoding="utf-8")

        self.assertIn("flow_execution", json_rep)
        self.assertIn("counts", json_rep)
        self.assertIn("flowchart TD", md_rep)
        self.assertIn("Executive Summary", md_rep)


if __name__ == "__main__":
    unittest.main()
