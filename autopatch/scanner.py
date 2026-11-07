"""Static security scanner backwards compatibility shim.
Redirects to SAST scanner module (Flow step E).
"""
from .sast import DEFAULT_EXCLUDES, SASTScanner, _dynamic_sql, _is_str, scan_source

__all__ = ["DEFAULT_EXCLUDES", "SASTScanner", "scan_source", "_dynamic_sql", "_is_str"]
