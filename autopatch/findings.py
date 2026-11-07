"""Normalized finding record shared by every pipeline stage."""
import hashlib
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    col: int
    snippet: str
    fingerprint: str
    title: str = ""
    severity: str = "medium"
    category: str = ""
    cwe: str = ""
    fixable: bool = False

    def to_dict(self):
        return asdict(self)


def make_fingerprint(rule_id: str, file: str, key: str) -> str:
    """Position-independent id, so a finding can be tracked across patches."""
    return hashlib.sha1(f"{rule_id}|{file}|{key}".encode()).hexdigest()[:10]
