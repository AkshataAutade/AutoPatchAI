"""Report generation: report.json (machine-readable) and report.md (human-readable)."""
import json

LABEL = {"accepted": "Accepted", "rejected": "Rejected (original preserved)",
         "manual_review": "Manual review"}


def write_reports(out, report):
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    c, m = report["counts"], report["metrics"]
    lines = [f"# AutoPatch AI report: {report['project']}", ""]
    if report["clean_scan"]:
        lines += ["**Clean scan.** No findings were detected.", ""]
    else:
        lines += [f"Found **{c['found']}** | accepted **{c['accepted']}** | "
                  f"rejected **{c['rejected']}** | manual review **{c['manual_review']}**", ""]
        lines += ["| # | Rule | Severity | Location | Outcome | Remediation time |",
                  "|---|------|----------|----------|---------|------------------|"]
        for i, r in enumerate(report["findings"], 1):
            lines.append(f"| {i} | {r['rule_id']} {r['cwe']} | {r['severity']} | "
                         f"{r['file']}:{r['line']} | {LABEL[r['status']]} | "
                         f"{r['remediation_seconds']:.3f}s |")
        lines.append("")
        for i, r in enumerate(report["findings"], 1):
            lines += [f"## {i}. {r['title']} ({r['file']}:{r['line']})",
                      f"- Outcome: {LABEL[r['status']]}. {r['reason']}"]
            if r["diff"]:
                lines += ["", "```diff", r["diff"].rstrip(), "```"]
            lines.append("")
    lines += ["## Time metrics", "", "| Stage | Seconds |", "|-------|---------|"]
    lines += [f"| {k} | {v} |" for k, v in m["stage_seconds"].items()]
    if m["mean_seconds_per_accepted_fix"] is not None:
        lines += ["", f"Mean time per accepted fix (repair + tests + rescan): "
                      f"**{m['mean_seconds_per_accepted_fix']}s**"]
    (out / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
