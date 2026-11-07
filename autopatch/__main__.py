"""AutoPatch AI CLI entry point.
Supports scanning, patch verification, interactive CLI review, and web dashboard server.
"""
import argparse
import sys
from pathlib import Path

from .orchestrator import NotAuthorized, run
from .review import run_cli_review
from .server import start_server


def main():
    ap = argparse.ArgumentParser(
        prog="autopatch",
        description="AutoPatch AI: Detect, classify, repair, and verify security vulnerabilities.",
    )
    ap.add_argument(
        "project",
        nargs="?",
        default="examples/vulnerable_app",
        help="Path to an authorized project directory (default: examples/vulnerable_app)",
    )
    ap.add_argument(
        "--out",
        default="autopatch-out",
        help="Output folder for reports, working copy, and patches (default: autopatch-out)",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Copy accepted patches back into the project (default: leave project untouched)",
    )
    ap.add_argument(
        "--test-cmd",
        help="Custom test command (default: python -m unittest discover)",
    )
    ap.add_argument(
        "--placeholder",
        help="SQL parameter placeholder, e.g. ? or %%s",
    )
    ap.add_argument(
        "--no-dast",
        action="store_true",
        help="Disable DAST runtime scanner",
    )
    ap.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI-Assisted Analysis / RAG extension",
    )
    ap.add_argument(
        "--review",
        action="store_true",
        help="Launch interactive terminal Developer Review mode after scanning",
    )
    ap.add_argument(
        "--serve",
        action="store_true",
        help="Launch the Developer Review web dashboard server",
    )
    ap.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for the review web server (default: 8765)",
    )

    args = ap.parse_args()

    # Serve mode
    if args.serve:
        start_server(port=args.port, project_dir=Path(args.project), output_dir=Path(args.out))
        return 0

    try:
        rep = run(
            repo=args.project,
            out=args.out,
            apply=args.apply,
            test_cmd=args.test_cmd,
            placeholder=args.placeholder,
            enable_dast=not args.no_dast,
            enable_ai=not args.no_ai,
        )
    except NotAuthorized as e:
        print(f"Not authorized: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"Stopped: {e}", file=sys.stderr)
        return 3

    c = rep["counts"]
    m = rep["metrics"]

    if rep["clean_scan"]:
        print("Clean scan: no findings.")
    else:
        print(
            f"Found {c['found']} (SAST: {c.get('sast_count', 0)}, DAST: {c.get('dast_count', 0)}): "
            f"accepted {c['accepted']}, rejected {c['rejected']}, "
            f"manual review {c['manual_review']}"
        )
    print(f"Total time: {m['total_seconds']}s. Reports: {args.out}/report.md and report.json")

    # Developer Review mode
    if args.review:
        run_cli_review(rep, Path(args.project))

    return 0


if __name__ == "__main__":
    sys.exit(main())
