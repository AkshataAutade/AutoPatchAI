"""Vulnerability Detection module (Flow step G).
Aggregates findings from both SAST and DAST scanners,
normalizes, deduplicates, and generates stable fingerprints.
"""
from typing import Any, Dict, List, Set, Tuple

from .findings import Finding, make_fingerprint


class VulnerabilityDetector:
    """Aggregates and normalizes multi-scanner detection outputs."""

    @staticmethod
    def detect(sast_raw: List[Dict[str, Any]], dast_raw: List[Dict[str, Any]]) -> List[Finding]:
        """Combine SAST and DAST raw findings into a unified, deduplicated list of Findings."""
        combined = list(sast_raw) + list(dast_raw)
        seen: Set[Tuple[str, str, int, int]] = set()
        findings: List[Finding] = []

        for item in combined:
            rule_id = item["rule_id"]
            file_path = item["file"]
            line = item.get("line", 1)
            col = item.get("col", 0)
            snippet = item.get("snippet", "")
            key = item.get("key", f"{rule_id}:{file_path}:{line}")
            scanner_type = item.get("scanner_type") or ("DAST" if rule_id.startswith("DAST") else "SAST")

            k = (rule_id, file_path, line, col)
            if k in seen:
                continue
            seen.add(k)

            fp = make_fingerprint(rule_id, file_path, key)
            finding = Finding(
                rule_id=rule_id,
                file=file_path,
                line=line,
                col=col,
                snippet=snippet,
                fingerprint=fp,
                scanner_type=scanner_type,
            )
            findings.append(finding)

        return findings


def normalize(raw: List[Dict[str, Any]]) -> List[Finding]:
    """Backward compatibility helper for normalizing a single raw findings list."""
    return VulnerabilityDetector.detect(raw, [])
