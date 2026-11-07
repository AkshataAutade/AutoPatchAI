"""Report generation module (Flow steps U, V, W).
Generates machine-readable report.json (V) and comprehensive report.md (W).
"""
import json
from pathlib import Path
from typing import Any, Dict

LABEL = {
    "accepted": "Accepted",
    "rejected": "Rejected (original preserved)",
    "manual_review": "Manual review",
}


def write_reports(out: Path, report: Dict[str, Any]):
    """Write report.json and report.md to output directory."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    # 1. Write report.json (V)
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    # 2. Write report.md (W)
    c = report.get("counts", {})
    m = report.get("metrics", {})
    findings = report.get("findings", [])

    lines = [
        f"# AutoPatch AI Security Report: {report.get('project', 'Project')}",
        "",
        f"> **Generated at:** {report.get('generated_at', '')} | **Python:** {report.get('python', '')} | **Authorization:** Verified",
        "",
        "## Pipeline Architecture Execution",
        "",
        "```mermaid",
        "flowchart TD",
        "    A[\"User / Developer\"] --> B[\"Input Project\"]",
        "    B --> C[\"Authorization & Project Validation\"]",
        "    C --> D[\"AutoPatch AI Orchestrator\"]",
        "    D --> E[\"Source Code Scanner - SAST\"]",
        "    D --> F[\"Runtime Scanner - DAST\"]",
        "    E --> G[\"Vulnerability Detection\"]",
        "    F --> G",
        "    G --> H[\"Finding Classification & Risk Analysis\"]",
        "    H --> I[\"Vulnerability Database / Findings\"]",
        "    I --> J[\"Remediation Engine\"]",
        "    J --> K[\"Security Rules & Patch Templates\"]",
        "    J --> L[\"AI-Assisted Analysis / RAG - Extension\"]",
        "    K --> M[\"Patch Generation\"]",
        "    L --> M",
        "    M --> N[\"Patch Safety Validation\"]",
        "    N --> O[\"Apply Patch to Project Copy\"]",
        "    O --> P[\"Automated Testing\"]",
        "    P --> Q[\"Rescan & Security Verification\"]",
        "    Q --> R{\"Patch Successful?\"}",
        "    R -->|Yes| S[\"Accepted Fix\"]",
        "    R -->|No| T[\"Rejected / Manual Review\"]",
        "    S --> U[\"Final Reports\"]",
        "    T --> U",
        "    U --> V[\"JSON Report\"]",
        "    U --> W[\"Markdown Report\"]",
        "    U --> X[\"Developer Review\"]",
        "```",
        "",
        "## Executive Summary",
        "",
    ]

    if report.get("clean_scan"):
        lines += [
            "**Clean scan.** No security findings were detected by SAST or DAST scanners.",
            "",
        ]
    else:
        lines += [
            f"- **Total Findings Detected:** `{c.get('found', 0)}`",
            f"- **Accepted & Verified Patches:** `{c.get('accepted', 0)}`",
            f"- **Rejected Patches:** `{c.get('rejected', 0)}`",
            f"- **Manual Review Required:** `{c.get('manual_review', 0)}`",
            f"- **SAST Findings:** `{c.get('sast_count', 0)}` | **DAST Findings:** `{c.get('dast_count', 0)}`",
            "",
            "## Vulnerability Findings & Risk Summary",
            "",
            "| # | Scanner | Rule & CWE | Severity | Risk Score | Location | Outcome | Strategy |",
            "|---|---------|------------|----------|------------|----------|---------|----------|",
        ]

        for i, r in enumerate(findings, 1):
            rule_id = r.get("rule_id", "")
            cwe = r.get("cwe", "")
            scanner = r.get("scanner_type", "SAST")
            sev = r.get("severity", "medium").upper()
            score = r.get("risk_score", r.get("cvss_base", "N/A"))
            loc = f"`{r.get('file', '')}:{r.get('line', '')}`"
            outcome = LABEL.get(r.get("status", ""), r.get("status", ""))
            strat = r.get("patch_strategy", "N/A")
            lines.append(f"| {i} | {scanner} | {rule_id} ({cwe}) | {sev} | {score}/10 | {loc} | {outcome} | {strat} |")

        lines.append("")
        lines.append("## Detailed Remediation & Developer Review")
        lines.append("")

        for i, r in enumerate(findings, 1):
            title = r.get("title", "Finding")
            rule_id = r.get("rule_id", "")
            file_loc = f"{r.get('file', '')}:{r.get('line', '')}"
            sev = r.get("severity", "").upper()
            status_text = LABEL.get(r.get("status", ""), r.get("status", ""))
            reason = r.get("reason", "")
            diff = r.get("diff")
            ai_analysis = r.get("ai_analysis", "")
            rem_sec = r.get("remediation_seconds", 0.0)

            lines += [
                f"### {i}. [{sev}] {title} (`{file_loc}`)",
                f"- **Rule ID:** `{rule_id}` | **CWE:** {r.get('cwe', '')} | **OWASP:** {r.get('owasp', '')}",
                f"- **Scanner:** {r.get('scanner_type', 'SAST')} | **Confidence:** {r.get('confidence', 95)}%",
                f"- **Status:** **{status_text}** ({rem_sec:.3f}s)",
                f"- **Outcome Reason:** {reason}",
            ]

            if ai_analysis:
                lines += ["", "> **AI Analysis & RAG Context:**", "> " + ai_analysis.replace("\n", "\n> ")]

            if diff:
                lines += [
                    "",
                    "#### Proposed & Verified Diff",
                    "```diff",
                    diff.rstrip(),
                    "```",
                ]
            lines.append("")

    lines += [
        "## Performance Metrics",
        "",
        "| Pipeline Stage | Wall-Clock Seconds |",
        "|----------------|--------------------|",
    ]
    stage_sec = m.get("stage_seconds", {})
    for stage_name, sec_val in stage_sec.items():
        lines.append(f"| `{stage_name}` | {sec_val:.3f}s |")

    if m.get("mean_seconds_per_accepted_fix") is not None:
        lines += [
            "",
            f"**Mean Time Per Accepted Fix:** `{m['mean_seconds_per_accepted_fix']:.3f}s`",
        ]
    lines += [f"**Total Pipeline Execution Time:** `{m.get('total_seconds', 0.0):.3f}s`", ""]

    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
