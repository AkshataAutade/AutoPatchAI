import argparse
import sys

from .orchestrator import NotAuthorized, run


def main():
    ap = argparse.ArgumentParser(prog="autopatch",
                                 description="Detect, repair and verify security findings.")
    ap.add_argument("project", help="path to an authorized project")
    ap.add_argument("--out", default="autopatch-out", help="output folder (default: autopatch-out)")
    ap.add_argument("--apply", action="store_true",
                    help="copy accepted patches back into the project (default: leave it untouched)")
    ap.add_argument("--test-cmd", help="custom test command (default: python -m unittest discover)")
    ap.add_argument("--placeholder", help="SQL parameter placeholder, e.g. ? or %%s")
    a = ap.parse_args()
    try:
        rep = run(a.project, a.out, apply=a.apply, test_cmd=a.test_cmd, placeholder=a.placeholder)
    except NotAuthorized as e:
        print(f"Not authorized: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"Stopped: {e}", file=sys.stderr)
        return 3
    c, m = rep["counts"], rep["metrics"]
    if rep["clean_scan"]:
        print("Clean scan: no findings.")
    else:
        print(f"Found {c['found']}: accepted {c['accepted']}, rejected {c['rejected']}, "
              f"manual review {c['manual_review']}")
    print(f"Total time: {m['total_seconds']}s. Reports: {a.out}/report.md and report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
