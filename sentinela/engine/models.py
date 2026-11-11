from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        return value if isinstance(value, Severity) else cls(str(value).strip().lower())


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Engine(str, Enum):
    RULE = "rule"
    TAINT = "taint"
    SECRET = "secret"  # noqa: S105 - nome do motor, não credencial
    BANDIT = "bandit"


DETERMINISTIC_ENGINES = frozenset(Engine)


@dataclass(frozen=True)
class TaintStep:
    line: int
    kind: str
    code: str


@dataclass
class Finding:
    rule_id: str
    title: str
    language: str
    file_path: str
    line: int
    end_line: int
    column: int
    severity: Severity
    cwe: str
    owasp: str
    message: str
    snippet: str
    engines: set[Engine] = field(default_factory=set)
    taint_path: list[TaintStep] = field(default_factory=list)
    remediation: str = ""
    safe_example: str = ""
    references: list[str] = field(default_factory=list)
    context: str = ""
    fingerprint: str = ""

    @property
    def confidence(self) -> str:

        if len(self.engines) >= 2 or Engine.TAINT in self.engines:
            return "high"
        if Engine.SECRET in self.engines:
            return "high"
        return "medium"

    def compute_fingerprint(self, scope: str = "") -> str:

        normalized = re.sub(r"\s+", " ", self.snippet.strip())
        raw = "|".join([scope, self.rule_id, self.file_path, normalized])
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:32]
        return self.fingerprint


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str
    language: str | None = None


@dataclass
class ScanResult:
    findings: list[Finding]
    files_scanned: int
    files_skipped: list[tuple[str, str]]
    languages: dict[str, int]
    duration_ms: int = 0
