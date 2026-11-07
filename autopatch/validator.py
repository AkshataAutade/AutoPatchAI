"""Authorization and Project Validation module (Flow step C).
Ensures project is explicitly authorized by an admin via .autopatch.json,
validates project structure, permissions, and configuration options.
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_NAME = ".autopatch.json"


class NotAuthorized(Exception):
    """Raised when project authorization is missing or invalid."""
    pass


class ValidationError(Exception):
    """Raised when project validation fails."""
    pass


@dataclass
class ValidationResult:
    authorized: bool = False
    valid: bool = False
    repo_path: Optional[Path] = None
    config: Dict[str, Any] = field(default_factory=dict)
    python_files_count: int = 0
    test_suite_detected: bool = False
    test_command: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "authorized": self.authorized,
            "valid": self.valid,
            "repo_path": str(self.repo_path) if self.repo_path else None,
            "config": self.config,
            "python_files_count": self.python_files_count,
            "test_suite_detected": self.test_suite_detected,
            "test_command": self.test_command,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def validate_project(repo_path: Path) -> ValidationResult:
    """Validate project existence, authorization, configuration, and file structure."""
    repo = Path(repo_path).resolve()
    result = ValidationResult(repo_path=repo)

    if not repo.exists():
        result.errors.append(f"Project directory does not exist: {repo}")
        return result

    if not repo.is_dir():
        result.errors.append(f"Project path is not a directory: {repo}")
        return result

    cfg_path = repo / CONFIG_NAME
    if not cfg_path.is_file():
        err = (
            f"Project '{repo.name}' is not authorized. A project administrator must create "
            f"{CONFIG_NAME} with '{{\"authorized\": true}}' in the repository root before AutoPatch "
            f"will scan or modify it."
        )
        result.errors.append(err)
        return result

    try:
        raw_cfg = cfg_path.read_text(encoding="utf-8")
        cfg = json.loads(raw_cfg)
    except Exception as e:
        result.errors.append(f"Invalid JSON format in {CONFIG_NAME}: {e}")
        return result

    if not isinstance(cfg, dict):
        result.errors.append(f"Configuration in {CONFIG_NAME} must be a JSON object.")
        return result

    result.config = cfg
    if cfg.get("authorized") is not True:
        err = f"{CONFIG_NAME} in '{repo.name}' does not set '\"authorized\": true'."
        result.errors.append(err)
        return result

    result.authorized = True

    # Validate structure & python files
    py_files = list(repo.rglob("*.py"))
    # Filter virtualenvs / git
    active_py = [
        p for p in py_files
        if not any(part in {".git", "__pycache__", "venv", ".venv", "node_modules"} for part in p.parts)
    ]
    result.python_files_count = len(active_py)
    if result.python_files_count == 0:
        result.warnings.append("No active Python (*.py) files found in project.")

    # Validate test setup
    test_cmd = cfg.get("test_command")
    tests_dir = repo / "tests"
    if test_cmd:
        result.test_suite_detected = True
        result.test_command = test_cmd
    elif tests_dir.is_dir():
        result.test_suite_detected = True
        result.test_command = "python -m unittest discover -s tests -t . -q"
    else:
        result.warnings.append("No 'tests/' directory or 'test_command' found. Automated test verification will run in no-op mode.")

    result.valid = len(result.errors) == 0
    return result


def load_config(repo: Path) -> dict:
    """Backward-compatible config loader that raises NotAuthorized if invalid."""
    res = validate_project(repo)
    if not res.authorized or not res.valid:
        raise NotAuthorized("\n".join(res.errors))
    return res.config

