"""CLI Developer Review module (Flow step X).
Provides an interactive terminal interface for developers to inspect findings,
review code diffs, read AI explanations, and approve or reject patches.
"""
import sys
from pathlib import Path
from typing import Any, Dict


def run_cli_review(report: Dict[str, Any], project_root: Path):
    """Interactive developer review loop in the terminal."""
    findings = report.get("findings", [])
    if not findings:
        print("\nNo findings to review.")
        return

    print("\n" + "=" * 70)
    print(f" DEVELOPER REVIEW: {report.get('project', 'Project')}")
    print("=" * 70)
    print(f"Total findings: {len(findings)} | Accepted: {report['counts'].get('accepted', 0)} | "
          f"Rejected: {report['counts'].get('rejected', 0)} | Manual Review: {report['counts'].get('manual_review', 0)}")
    print("-" * 70)

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "medium").upper()
        scanner = f.get("scanner_type", "SAST")
        print(f"\n[{i}/{len(findings)}] [{sev}] [{scanner}] {f.get('title')}")
        print(f"Location: {f.get('file')}:{f.get('line')}")
        print(f"Rule: {f.get('rule_id')} | CWE: {f.get('cwe')} | Status: {f.get('status').upper()}")
        print(f"Reason: {f.get('reason')}")

        if f.get("diff"):
            print("\n--- Proposed Patch Diff ---")
            for line in f["diff"].splitlines()[:15]:
                if line.startswith("+"):
                    print(f"\033[92m{line}\033[0m" if sys.stdout.isatty() else line)
                elif line.startswith("-"):
                    print(f"\033[91m{line}\033[0m" if sys.stdout.isatty() else line)
                else:
                    print(line)
            if len(f["diff"].splitlines()) > 15:
                print("... (truncated diff)")

        ai_exp = f.get("ai_analysis")
        if ai_exp:
            print("\n[AI/RAG Explanation Available]")

        print("\nOptions: [n]ext finding, [v]iew AI analysis, [q]uit review")
        try:
            choice = input("Enter choice (n/v/q) [n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting review.")
            break

        if choice == "v" and ai_exp:
            print("\n--- AI-Assisted Security Analysis & RAG Context ---")
            print(ai_exp)
            print("-" * 50)
            try:
                input("Press Enter to continue...")
            except (EOFError, KeyboardInterrupt):
                break
        elif choice == "q":
            print("Review completed.")
            break

    print("\nReview session ended.")

