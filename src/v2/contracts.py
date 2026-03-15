from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class AdjudicationDecision(str, Enum):
    CONSENSUS = "consensus"
    DISPUTE = "dispute"


class FinalStatus(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    REJECTED = "rejected"
    NEEDS_HUMAN_REVIEW = "needs-human-review"


@dataclass
class EvidenceLocation:
    file: str
    line: int
    reason: str


@dataclass
class ModelVerdict:
    model: str
    is_vulnerable: bool
    summary: str
    evidence_locations: list[EvidenceLocation] = field(default_factory=list)
    cwe_id: str | None = None
    cvss_estimate: float | None = None
    reproduction_hypothesis: str = ""
    confidence: float = 0.0
    raw_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "is_vulnerable": self.is_vulnerable,
            "summary": self.summary,
            "evidence_locations": [asdict(x) for x in self.evidence_locations],
            "cwe_id": self.cwe_id,
            "cvss_estimate": self.cvss_estimate,
            "reproduction_hypothesis": self.reproduction_hypothesis,
            "confidence": self.confidence,
            "raw_output": self.raw_output,
        }


@dataclass
class AdjudicationRecord:
    round_index: int
    decision: AdjudicationDecision
    reason: str
    evidence_sufficient: bool
    consensus_vulnerable: bool | None
    consensus_confidence: float
    codex: ModelVerdict | None = None
    claude: ModelVerdict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "decision": self.decision.value,
            "reason": self.reason,
            "evidence_sufficient": self.evidence_sufficient,
            "consensus_vulnerable": self.consensus_vulnerable,
            "consensus_confidence": self.consensus_confidence,
            "codex": self.codex.to_dict() if self.codex else None,
            "claude": self.claude.to_dict() if self.claude else None,
        }


@dataclass
class ValidationEvidence:
    run_index: int
    verdict: str
    exit_code: int
    is_positive: bool
    stdout_tail: str = ""
    stderr_tail: str = ""
    asan_report: str = ""
    trigger_kind: str = ""
    trigger_command: str = ""
    pov_preview: str = ""
    pov_artifact: str = ""
    pov_sha256: str = ""
    plan_confidence: float = 0.0
    plan_rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingAnalysis:
    finding_id: str
    rule_id: str
    severity: str
    message: str
    primary_file: str
    primary_line: int
    codeql_finding: dict[str, Any]
    adjudication_history: list[AdjudicationRecord] = field(default_factory=list)
    final_decision: str = "needs-human-review"
    consensus_vulnerable: bool | None = None
    confidence: float = 0.0
    stop_reason: str = ""
    consecutive_failures: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "primary_file": self.primary_file,
            "primary_line": self.primary_line,
            "codeql_finding": self.codeql_finding,
            "adjudication_history": [x.to_dict() for x in self.adjudication_history],
            "final_decision": self.final_decision,
            "consensus_vulnerable": self.consensus_vulnerable,
            "confidence": self.confidence,
            "stop_reason": self.stop_reason,
            "consecutive_failures": self.consecutive_failures,
        }


@dataclass
class FinalFinding:
    finding_id: str
    rule_id: str
    severity: str
    message: str
    primary_file: str
    primary_line: int
    final_status: FinalStatus
    evidence_score: float
    consensus_vulnerable: bool | None
    adjudication_history: list[AdjudicationRecord] = field(default_factory=list)
    validation_evidence: list[ValidationEvidence] = field(default_factory=list)
    stop_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "primary_file": self.primary_file,
            "primary_line": self.primary_line,
            "final_status": self.final_status.value,
            "evidence_score": self.evidence_score,
            "consensus_vulnerable": self.consensus_vulnerable,
            "adjudication_history": [x.to_dict() for x in self.adjudication_history],
            "validation_evidence": [x.to_dict() for x in self.validation_evidence],
            "stop_reason": self.stop_reason,
        }


@dataclass
class ScanTarget:
    target_id: str
    name: str
    snapshot_root: str
    original_source: str
    commit: str | None
    language: str
    scan_mode: str
    codeql_db_path: str
    pov_file: str | None
    file_index: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanBundle:
    run_id: str
    created_at: str
    detect_only: bool
    targets: list[ScanTarget] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "detect_only": self.detect_only,
            "targets": [t.to_dict() for t in self.targets],
        }


@dataclass
class AnalyzeTargetResult:
    target_id: str
    snapshot_root: str
    language_profile: dict[str, Any]
    findings_total: int
    findings_selected: int
    findings: list[FindingAnalysis] = field(default_factory=list)
    model_contribution: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "snapshot_root": self.snapshot_root,
            "language_profile": self.language_profile,
            "findings_total": self.findings_total,
            "findings_selected": self.findings_selected,
            "findings": [f.to_dict() for f in self.findings],
            "model_contribution": self.model_contribution,
        }


@dataclass
class AnalyzeResult:
    run_id: str
    generated_at: str
    topology: str
    max_rounds: int
    targets: list[AnalyzeTargetResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "topology": self.topology,
            "max_rounds": self.max_rounds,
            "targets": [t.to_dict() for t in self.targets],
        }


@dataclass
class ValidateTargetResult:
    target_id: str
    snapshot_root: str
    final_findings: list[FinalFinding] = field(default_factory=list)
    model_contribution: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "snapshot_root": self.snapshot_root,
            "final_findings": [f.to_dict() for f in self.final_findings],
            "model_contribution": self.model_contribution,
        }


@dataclass
class ValidationResult:
    run_id: str
    generated_at: str
    verify_runs: int
    strategy: str
    targets: list[ValidateTargetResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "verify_runs": self.verify_runs,
            "strategy": self.strategy,
            "targets": [t.to_dict() for t in self.targets],
        }
