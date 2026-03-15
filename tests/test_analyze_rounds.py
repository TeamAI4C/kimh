from dataclasses import dataclass

from src.v2.adjudicator import AdjudicationPolicy
from src.v2.analyze import run_adjudicated_rounds, run_codex_single_pass
from src.v2.contracts import ScanTarget
from src.v2.llm_cli import CLIModelExecutor
from src.v2.llm_cli import CLIExecutionResult


@dataclass
class FakeRunner:
    rounds: list[dict[str, CLIExecutionResult]]
    idx: int = 0

    def run_round(self, prompt: str, codex_cmd: str, claude_cmd: str) -> dict[str, CLIExecutionResult]:
        out = self.rounds[self.idx]
        self.idx += 1
        return out


@dataclass
class FakeExecutor(CLIModelExecutor):
    result: CLIExecutionResult

    def __init__(self, result: CLIExecutionResult):
        super().__init__(timeout_seconds=1)
        self.result = result

    def run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:
        return self.result


def _ok(model: str, vulnerable: bool, confidence: float = 0.9) -> CLIExecutionResult:
    payload = {
        "is_vulnerable": vulnerable,
        "summary": "ok",
        "evidence_locations": [{"file": "src/a.c", "line": 12, "reason": "sink"}],
        "cwe_id": "CWE-79",
        "cvss_estimate": 8.1,
        "reproduction_hypothesis": "send payload",
        "confidence": confidence,
    }
    import json

    return CLIExecutionResult(model=model, ok=True, returncode=0, stdout=json.dumps(payload), stderr="")


def _fail(model: str) -> CLIExecutionResult:
    return CLIExecutionResult(model=model, ok=False, returncode=1, stdout="", stderr="err", error="bad")


def _target() -> ScanTarget:
    return ScanTarget(
        target_id="t-01",
        name="t",
        snapshot_root="/tmp/x",
        original_source="/tmp/x",
        commit=None,
        language="cpp",
        scan_mode="pack",
        codeql_db_path="/tmp/db",
        pov_file=None,
        file_index=[],
    )


def _finding() -> dict:
    return {
        "rule_id": "cpp/use-after-free",
        "severity": "error",
        "message": "uaf",
        "chain": [{"file": "a.c", "line": 10, "action": "source", "snippet": "x"}],
    }


def _template() -> str:
    return (
        "Schema:\\n{{SCHEMA_JSON}}\\n"
        "Round={{ROUND_INDEX}}\\n"
        "Target={{TARGET_NAME}}\\n"
        "Root={{SNAPSHOT_ROOT}}\\n"
        "Skills:\\n{{SKILL_REFERENCES}}\\n"
        "Finding:\\n{{CODEQL_FINDING_JSON}}\\n"
        "History:\\n{{ADJUDICATION_HISTORY_JSON}}\\n"
    )


def test_stops_on_consensus() -> None:
    runner = FakeRunner(rounds=[{"codex": _ok("codex", True), "claude": _ok("claude", True)}])
    contrib = {"codex": {"valid_rounds": 0, "consensus_supports": 0}, "claude": {"valid_rounds": 0, "consensus_supports": 0}}

    result = run_adjudicated_rounds(
        finding_id="f1",
        finding=_finding(),
        target=_target(),
        max_rounds=6,
        codex_cli="codex",
        claude_cli="claude",
        runner=runner,  # type: ignore[arg-type]
        policy=AdjudicationPolicy(),
        max_consecutive_failures=2,
        model_contribution=contrib,
        prompt_template=_template(),
        skill_references=["skills/findvuln-analyze/SKILL.md"],
    )
    assert result.final_decision == "consensus"
    assert result.consensus_vulnerable is True


def test_needs_human_review_after_consecutive_failures() -> None:
    rounds = [
        {"codex": _fail("codex"), "claude": _ok("claude", True)},
        {"codex": _fail("codex"), "claude": _ok("claude", True)},
    ]
    runner = FakeRunner(rounds=rounds)
    contrib = {"codex": {"valid_rounds": 0, "consensus_supports": 0}, "claude": {"valid_rounds": 0, "consensus_supports": 0}}

    result = run_adjudicated_rounds(
        finding_id="f1",
        finding=_finding(),
        target=_target(),
        max_rounds=6,
        codex_cli="codex",
        claude_cli="claude",
        runner=runner,  # type: ignore[arg-type]
        policy=AdjudicationPolicy(),
        max_consecutive_failures=2,
        model_contribution=contrib,
        prompt_template=_template(),
        skill_references=["skills/findvuln-analyze/SKILL.md"],
    )
    assert result.final_decision == "needs-human-review"
    assert "codex failed" in result.stop_reason


def test_codex_single_pass_consensus() -> None:
    executor = FakeExecutor(_ok("codex", True, confidence=0.95))
    contrib = {"codex": {"valid_rounds": 0, "consensus_supports": 0}, "claude": {"valid_rounds": 0, "consensus_supports": 0}}
    result = run_codex_single_pass(
        finding_id="f1",
        finding=_finding(),
        target=_target(),
        codex_cli="codex",
        executor=executor,
        policy=AdjudicationPolicy(min_consensus_confidence=0.6, require_evidence=True),
        model_contribution=contrib,
        prompt_template=_template(),
        skill_references=["skills/findvuln-analyze/SKILL.md"],
    )
    assert result.final_decision == "consensus"
    assert result.consensus_vulnerable is True
    assert len(result.adjudication_history) == 1
    assert result.adjudication_history[0].claude is None


def test_codex_single_pass_needs_human_review_when_confidence_low() -> None:
    executor = FakeExecutor(_ok("codex", True, confidence=0.2))
    contrib = {"codex": {"valid_rounds": 0, "consensus_supports": 0}, "claude": {"valid_rounds": 0, "consensus_supports": 0}}
    result = run_codex_single_pass(
        finding_id="f1",
        finding=_finding(),
        target=_target(),
        codex_cli="codex",
        executor=executor,
        policy=AdjudicationPolicy(min_consensus_confidence=0.6, require_evidence=True),
        model_contribution=contrib,
        prompt_template=_template(),
        skill_references=["skills/findvuln-analyze/SKILL.md"],
    )
    assert result.final_decision == "needs-human-review"
