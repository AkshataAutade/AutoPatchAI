"""Python orchestrator: runs the whole detect -> repair -> verify flow and records metrics."""
import difflib
import json
import platform
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from .findings import Finding, make_fingerprint
from .repair import FIXERS
from .report import write_reports
from .rules import RULES, SEVERITY_ORDER
from .scanner import DEFAULT_EXCLUDES, scan_source
from .tester import run_tests

CONFIG_NAME = ".autopatch.json"


class NotAuthorized(Exception):
    pass


def load_config(repo: Path) -> dict:
    cfg_path = repo / CONFIG_NAME
    if not cfg_path.is_file():
        raise NotAuthorized(
            f"{repo.name} is not authorized. A project admin must add {CONFIG_NAME} "
            f'with {{"authorized": true}} before AutoPatch will scan or change it.')
    cfg = json.loads(cfg_path.read_text())
    if cfg.get("authorized") is not True:
        raise NotAuthorized(f'{CONFIG_NAME} in {repo.name} does not set "authorized": true.')
    return cfg


def scan_tree(root: Path, excludes, disabled):
    raw, skipped = [], []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root)
        if any(part in excludes for part in rel.parts[:-1]):
            continue
        found = scan_source(p.read_text(encoding="utf-8"), rel.as_posix())
        if found is None:
            skipped.append(rel.as_posix())
            continue
        raw.extend(r for r in found if r["rule_id"] not in disabled)
    return raw, skipped


def normalize(raw):
    seen, out = set(), []
    for r in raw:
        k = (r["rule_id"], r["file"], r["line"], r["col"])
        if k in seen:
            continue
        seen.add(k)
        out.append(Finding(rule_id=r["rule_id"], file=r["file"], line=r["line"], col=r["col"],
                           snippet=r["snippet"],
                           fingerprint=make_fingerprint(r["rule_id"], r["file"], r["key"])))
    return out


def classify(findings):
    for f in findings:
        meta = RULES[f.rule_id]
        f.title, f.severity, f.category = meta["title"], meta["severity"], meta["category"]
        f.cwe, f.fixable = meta["cwe"], meta["fixable"] and f.rule_id in FIXERS
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))


def full_scan(root, excludes, disabled):
    raw, skipped = scan_tree(root, excludes, disabled)
    return classify(normalize(raw)), skipped


def _copy_project(repo: Path, work: Path, out: Path):
    def ignore(d, names):
        skip = {".git", "__pycache__", ".autopatch", "venv", ".venv"}
        return [n for n in names if n in skip or (Path(d) / n).resolve() == out]
    shutil.copytree(repo, work, ignore=ignore)


def run(repo, out, apply=False, test_cmd=None, placeholder=None):
    started = time.perf_counter()
    repo, out = Path(repo).resolve(), Path(out).resolve()
    cfg = load_config(repo)  # A -> B: only authorized projects continue
    excludes = DEFAULT_EXCLUDES | set(cfg.get("exclude_dirs", []))
    disabled = set(cfg.get("disabled_rules", []))
    test_cmd = test_cmd or cfg.get("test_command")
    ctx = {"placeholder": placeholder or cfg.get("placeholder", "?")}

    if out.exists():
        shutil.rmtree(out)
    work, originals, patches, rejected_dir = (out / "work", out / "originals",
                                              out / "patches", out / "rejected")
    for d in (originals, patches, rejected_dir):
        d.mkdir(parents=True)
    timings = {}

    t = time.perf_counter()
    _copy_project(repo, work, out)
    timings["copy_project"] = time.perf_counter() - t

    baseline = run_tests(work, test_cmd)
    timings["baseline_tests"] = baseline["seconds"]
    if not baseline["ok"]:
        raise RuntimeError("Baseline tests fail before any change; fix them first.\n"
                           + baseline["output"])

    t = time.perf_counter()  # C: run security scan
    current, skipped = full_scan(work, excludes, disabled)
    timings["scan"] = time.perf_counter() - t
    initial = list(current)

    results, attempted, saved_originals, n = [], set(), set(), 0
    manual_seen = set()
    while True:  # F..M: classify, then repair one finding at a time
        queue = [f for f in current if f.fingerprint not in attempted]
        if not queue:
            break
        f = queue[0]
        attempted.add(f.fingerprint)
        res = dict(f.to_dict(), status="", reason="", repair_seconds=0.0, test_seconds=0.0,
                   rescan_seconds=0.0, remediation_seconds=0.0, patch_file=None, diff=None)

        fixer = FIXERS.get(f.rule_id) if f.fixable else None
        if fixer is None:  # G: no supported repair rule -> H
            res.update(status="manual_review", reason="No supported automatic repair rule.")
            results.append(res)
            continue

        path = work / f.file
        before = path.read_text(encoding="utf-8")
        t = time.perf_counter()
        after = fixer(before, f, ctx)  # I: generate patch
        res["repair_seconds"] = time.perf_counter() - t
        if after is None or after == before:
            res.update(status="manual_review",
                       reason="Rule is supported, but this code shape cannot be repaired safely "
                              "automatically.")
            res["remediation_seconds"] = res["repair_seconds"]
            results.append(res)
            continue

        n += 1
        orig_file = originals / f.file
        if f.file not in saved_originals:  # original is always preserved
            orig_file.parent.mkdir(parents=True, exist_ok=True)
            orig_file.write_text(before, encoding="utf-8")
            saved_originals.add(f.file)
        diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                            f"a/{f.file}", f"b/{f.file}"))
        path.write_text(after, encoding="utf-8")

        tests = run_tests(work, test_cmd)  # J: automated tests ...
        res["test_seconds"] = tests["seconds"]
        t = time.perf_counter()
        rescan, _ = full_scan(work, excludes, disabled)  # ... and rescan
        res["rescan_seconds"] = time.perf_counter() - t

        before_fps = {x.fingerprint for x in current}
        after_fps = {x.fingerprint for x in rescan}
        problems = []
        if not tests["ok"]:
            problems.append("automated tests failed after the patch")
        if f.fingerprint in after_fps:
            problems.append("the finding is still present after rescan")
        if after_fps - before_fps:
            problems.append("the patch introduced new findings")

        name = f"{n:02d}-{f.rule_id}-{f.file.replace('/', '_')}.diff"
        if not problems:  # K yes -> L: accept
            (patches / name).write_text(diff, encoding="utf-8")
            res.update(status="accepted", reason="Tests pass and rescan no longer reports it.",
                       patch_file=f"patches/{name}", diff=diff)
            current = rescan
        else:  # K no -> M: reject and restore the original
            (rejected_dir / name).write_text(diff, encoding="utf-8")
            path.write_text(before, encoding="utf-8")
            res.update(status="rejected", reason="; ".join(problems).capitalize() + ".",
                       patch_file=f"rejected/{name}", diff=diff)
            if not tests["ok"]:
                res["test_output"] = tests["output"]
        res["remediation_seconds"] = (res["repair_seconds"] + res["test_seconds"]
                                      + res["rescan_seconds"])
        results.append(res)

    if apply:
        for rel in saved_originals:
            if (work / rel).read_text(encoding="utf-8") != (originals / rel).read_text(encoding="utf-8"):
                shutil.copyfile(work / rel, repo / rel)

    counts = {s: sum(1 for r in results if r["status"] == s)
              for s in ("accepted", "rejected", "manual_review")}
    fixed_times = [r["remediation_seconds"] for r in results if r["status"] == "accepted"]
    timings["total"] = time.perf_counter() - started  # N: record metrics
    report = dict(
        project=repo.name,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        python=platform.python_version(),
        authorized=True,
        clean_scan=not initial,
        baseline_tests_ok=baseline["ok"],
        applied_to_source=bool(apply),
        files_skipped_unparsable=skipped,
        counts=dict(found=len(initial), **counts),
        metrics=dict(
            stage_seconds={k: round(v, 3) for k, v in timings.items()},
            mean_seconds_per_accepted_fix=round(sum(fixed_times) / len(fixed_times), 3)
            if fixed_times else None,
            total_seconds=round(timings["total"], 3),
        ),
        findings=results,
    )
    write_reports(out, report)
    return report
