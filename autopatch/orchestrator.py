"""AutoPatch AI Orchestrator: executes the complete end-to-end security pipeline
according to the architectural flow (Steps A through X).
"""
import difflib
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .dast import DASTScanner
from .detector import VulnerabilityDetector
from .findings import Finding
from .rag_engine import RAGExtension
from .remediation import RemediationEngine
from .report import write_reports
from .risk import RiskAnalyzer
from .safety import validate_patch_safety
from .sast import SASTScanner
from .tester import run_tests
from .validator import NotAuthorized, validate_project


def _copy_project(repo: Path, work: Path, out: Path):
    def ignore(d, names):
        skip = {".git", "__pycache__", ".autopatch", "venv", ".venv"}
        return [n for n in names if n in skip or (Path(d) / n).resolve() == out]
    shutil.copytree(repo, work, ignore=ignore)


def run_full_scan(
    work_dir: Path,
    sast_scanner: SASTScanner,
    dast_scanner: DASTScanner,
) -> tuple[List[Finding], List[str]]:
    """Execute SAST (Step E) and DAST (Step F) and merge in Vulnerability Detection (Step G)."""
    sast_raw, skipped = sast_scanner.scan_tree(work_dir)
    dast_raw = dast_scanner.scan_runtime(work_dir)
    detected = VulnerabilityDetector.detect(sast_raw, dast_raw)
    classified = RiskAnalyzer.analyze(detected)
    return classified, skipped


def run(
    repo: str | Path,
    out: str | Path,
    apply: bool = False,
    test_cmd: Optional[str] = None,
    placeholder: Optional[str] = None,
    enable_dast: bool = True,
    enable_ai: bool = True,
) -> Dict[str, Any]:
    """Execute the end-to-end AutoPatch pipeline matching flowchart steps A through X."""
    started = time.perf_counter()
    repo, out = Path(repo).resolve(), Path(out).resolve()

    # Step A -> B -> C: Input Project & Authorization/Validation
    val_res = validate_project(repo)
    if not val_res.authorized or not val_res.valid:
        raise NotAuthorized("\n".join(val_res.errors))

    cfg = val_res.config
    excludes = set(cfg.get("exclude_dirs", [])) | {
        ".git", "__pycache__", "venv", ".venv", "tests", "node_modules", ".autopatch"
    }
    disabled = set(cfg.get("disabled_rules", []))
    test_cmd = test_cmd or cfg.get("test_command")
    ctx = {"placeholder": placeholder or cfg.get("placeholder", "?")}

    # Step D: AutoPatch AI Orchestrator Setup
    if out.exists():
        shutil.rmtree(out)
    work = out / "work"
    originals = out / "originals"
    patches = out / "patches"
    rejected_dir = out / "rejected"

    for d in (originals, patches, rejected_dir):
        d.mkdir(parents=True, exist_ok=True)

    timings: Dict[str, float] = {}
    flow_execution: Dict[str, Any] = {
        "A_user_input": {"status": "completed", "project": repo.name},
        "B_input_project": {"status": "completed", "path": str(repo)},
        "C_authorization_validation": {"status": "completed", "details": val_res.to_dict()},
        "D_orchestrator_init": {"status": "in_progress"},
    }

    # Isolated project copy
    t = time.perf_counter()
    _copy_project(repo, work, out)
    timings["copy_project"] = time.perf_counter() - t

    # Baseline tests verification
    baseline = run_tests(work, test_cmd)
    timings["baseline_tests"] = baseline["seconds"]
    if not baseline["ok"]:
        flow_execution["D_orchestrator_init"]["status"] = "failed"
        flow_execution["D_orchestrator_init"]["error"] = "Baseline tests failed"
        raise RuntimeError("Baseline tests fail before any changes; fix them first.\n" + baseline["output"])

    flow_execution["D_orchestrator_init"]["status"] = "completed"

    # Step E: Source Code Scanner - SAST
    t = time.perf_counter()
    sast_scanner = SASTScanner(excludes=excludes, disabled_rules=disabled)
    sast_raw, skipped = sast_scanner.scan_tree(work)
    timings["sast_scan"] = time.perf_counter() - t
    flow_execution["E_sast_scanner"] = {"status": "completed", "findings_count": len(sast_raw)}

    # Step F: Runtime Scanner - DAST
    t = time.perf_counter()
    dast_scanner = DASTScanner(excludes=excludes, disabled_rules=disabled) if enable_dast else None
    dast_raw = dast_scanner.scan_runtime(work) if (dast_scanner and enable_dast) else []
    timings["dast_scan"] = time.perf_counter() - t
    flow_execution["F_dast_scanner"] = {"status": "completed", "findings_count": len(dast_raw)}

    # Step G: Vulnerability Detection
    detected = VulnerabilityDetector.detect(sast_raw, dast_raw)
    flow_execution["G_vulnerability_detection"] = {"status": "completed", "total_detected": len(detected)}

    # Step H & I: Finding Classification & Risk Analysis / Vulnerability Database
    t = time.perf_counter()
    current = RiskAnalyzer.analyze(detected)
    timings["risk_analysis"] = time.perf_counter() - t
    initial = list(current)
    flow_execution["H_risk_analysis"] = {"status": "completed", "classified_count": len(current)}
    flow_execution["I_vuln_database"] = {"status": "completed", "queried_rules": list({f.rule_id for f in current})}

    # Step J: Remediation Engine initialization
    remediation_engine = RemediationEngine(enable_ai=enable_ai)
    rag_engine = RAGExtension() if enable_ai else None

    # Attach AI analysis & RAG context to all initial findings
    ai_analysis_map: Dict[str, str] = {}
    for f in initial:
        if rag_engine:
            try:
                target_file = work / f.file
                code_text = target_file.read_text(encoding="utf-8") if target_file.exists() else ""
                f.ai_analysis = rag_engine.generate_analysis(f, code_text)
            except Exception:
                f.ai_analysis = f.explanation
        ai_analysis_map[f.fingerprint] = f.ai_analysis

    results: List[Dict[str, Any]] = []
    attempted: Set[str] = set()
    saved_originals: Set[str] = set()
    patch_counter = 0

    # Remediation & Verification Loop (Steps J through R)
    while True:
        queue = [f for f in current if f.fingerprint not in attempted]
        if not queue:
            break
        f = queue[0]
        attempted.add(f.fingerprint)
        if not f.ai_analysis:
            f.ai_analysis = ai_analysis_map.get(f.fingerprint, f.explanation)

        res = dict(
            f.to_dict(),
            status="",
            reason="",
            repair_seconds=0.0,
            test_seconds=0.0,
            rescan_seconds=0.0,
            remediation_seconds=0.0,
            patch_file=None,
            diff=None,
            patch_strategy="",
            safety_validation_ok=False,
            safety_issues=[],
            ai_analysis=f.ai_analysis or ai_analysis_map.get(f.fingerprint, f.explanation),
        )

        path = work / f.file
        if not path.is_file():
            res.update(status="manual_review", reason="Target file not found in working copy.")
            results.append(res)
            continue

        before = path.read_text(encoding="utf-8")

        # Step J, K, L, M: Remediation Engine -> Rules & Templates / AI-Assisted RAG -> Patch Generation
        t = time.perf_counter()
        candidate = remediation_engine.remediate(f, before, ctx)
        res["repair_seconds"] = time.perf_counter() - t
        res["patch_strategy"] = candidate.strategy

        if candidate.after_code is None or candidate.after_code == before:
            res.update(
                status="manual_review",
                reason=candidate.notes,
                remediation_seconds=res["repair_seconds"],
            )
            results.append(res)
            continue

        after = candidate.after_code

        # Step N: Patch Safety Validation
        is_safe, safety_issues = validate_patch_safety(before, after, f)
        res["safety_validation_ok"] = is_safe
        res["safety_issues"] = safety_issues

        if not is_safe:
            # Patch failed safety validation -> cannot be applied
            res.update(
                status="rejected",
                reason=f"Patch safety validation failed: {'; '.join(safety_issues)}",
                remediation_seconds=res["repair_seconds"],
            )
            results.append(res)
            continue

        # Step O: Apply Patch to Project Copy
        patch_counter += 1
        orig_file = originals / f.file
        if f.file not in saved_originals:
            orig_file.parent.mkdir(parents=True, exist_ok=True)
            orig_file.write_text(before, encoding="utf-8")
            saved_originals.add(f.file)

        diff = "".join(difflib.unified_diff(
            before.splitlines(True), after.splitlines(True),
            f"a/{f.file}", f"b/{f.file}"
        ))
        path.write_text(after, encoding="utf-8")

        # Step P: Automated Testing
        test_run = run_tests(work, test_cmd)
        res["test_seconds"] = test_run["seconds"]

        # Step Q: Rescan & Security Verification (SAST + DAST)
        t = time.perf_counter()
        rescan_findings, _ = run_full_scan(work, sast_scanner, dast_scanner)
        res["rescan_seconds"] = time.perf_counter() - t

        before_fps = {x.fingerprint for x in current}
        after_fps = {x.fingerprint for x in rescan_findings}
        problems = []

        if not test_run["ok"]:
            problems.append("automated tests failed after applying the patch")
        if f.fingerprint in after_fps:
            problems.append("the finding is still reported by scanner after rescan")
        if after_fps - before_fps:
            problems.append("the patch introduced new security findings")

        # Step R: Patch Successful? Decision
        diff_name = f"{patch_counter:02d}-{f.rule_id}-{f.file.replace('/', '_').replace('\\', '_')}.diff"

        if not problems:
            # Step S: Accepted Fix
            (patches / diff_name).write_text(diff, encoding="utf-8")
            res.update(
                status="accepted",
                reason="Patch passed safety checks, project tests passed, and rescan verified fix.",
                patch_file=f"patches/{diff_name}",
                diff=diff,
            )
            current = rescan_findings
        else:
            # Step T: Rejected / Manual Review
            (rejected_dir / diff_name).write_text(diff, encoding="utf-8")
            path.write_text(before, encoding="utf-8")  # Revert
            res.update(
                status="rejected",
                reason="; ".join(problems).capitalize() + ".",
                patch_file=f"rejected/{diff_name}",
                diff=diff,
            )
            if not test_run["ok"]:
                res["test_output"] = test_run["output"]

        res["remediation_seconds"] = (
            res["repair_seconds"] + res["test_seconds"] + res["rescan_seconds"]
        )
        results.append(res)

    # Optional: Apply accepted fixes back to source repository
    if apply:
        for rel in saved_originals:
            if (work / rel).read_text(encoding="utf-8") != (originals / rel).read_text(encoding="utf-8"):
                shutil.copyfile(work / rel, repo / rel)

    # Step U: Final Reports compilation
    counts = {
        s: sum(1 for r in results if r["status"] == s)
        for s in ("accepted", "rejected", "manual_review")
    }
    sast_count = sum(1 for r in results if r.get("scanner_type") == "SAST")
    dast_count = sum(1 for r in results if r.get("scanner_type") == "DAST")
    fixed_times = [r["remediation_seconds"] for r in results if r["status"] == "accepted"]

    timings["total"] = time.perf_counter() - started

    flow_execution.update({
        "J_remediation_engine": {"status": "completed"},
        "K_security_rules": {"status": "completed"},
        "L_ai_rag_extension": {"status": "completed", "enabled": enable_ai},
        "M_patch_generation": {"status": "completed", "patches_generated": patch_counter},
        "N_patch_safety_validation": {"status": "completed"},
        "O_apply_to_project_copy": {"status": "completed"},
        "P_automated_testing": {"status": "completed"},
        "Q_rescan_verification": {"status": "completed"},
        "R_decision": {"status": "completed", "counts": counts},
        "S_accepted": {"status": "completed", "count": counts["accepted"]},
        "T_rejected": {"status": "completed", "count": counts["rejected"] + counts["manual_review"]},
        "U_final_reports": {"status": "completed"},
        "V_json_report": {"status": "completed", "path": str(out / "report.json")},
        "W_markdown_report": {"status": "completed", "path": str(out / "report.md")},
        "X_developer_review": {"status": "ready"},
    })

    report = {
        "project": repo.name,
        "repo_path": str(repo),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "authorized": True,
        "clean_scan": not initial,
        "baseline_tests_ok": baseline["ok"],
        "applied_to_source": bool(apply),
        "files_skipped_unparsable": skipped,
        "counts": {
            "found": len(initial),
            "sast_count": sast_count,
            "dast_count": dast_count,
            **counts,
        },
        "metrics": {
            "stage_seconds": {k: round(v, 3) for k, v in timings.items()},
            "mean_seconds_per_accepted_fix": (
                round(sum(fixed_times) / len(fixed_times), 3) if fixed_times else None
            ),
            "total_seconds": round(timings["total"], 3),
        },
        "findings": results,
        "flow_execution": flow_execution,
    }

    # Step V & W: JSON and Markdown Reports
    write_reports(out, report)
    return report
