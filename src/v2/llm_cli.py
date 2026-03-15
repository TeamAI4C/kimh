from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.v2.contracts import EvidenceLocation, ModelVerdict


@dataclass
class CLIExecutionResult:
    model: str
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    error: str = ""


@dataclass
class TriggerPlan:
    model: str
    should_attempt: bool
    trigger_kind: str
    execution_target: str = ""
    prepare_commands: list[str] = field(default_factory=list)
    verify_command: str = ""
    command: str = ""
    pov_stdin: str = ""
    expected_signal: str = ""
    confidence: float = 0.0
    rationale: str = ""
    raw_output: str = ""


class CLIModelExecutor:
    def __init__(self, timeout_seconds: int | None = 300):
        if timeout_seconds is None:
            self.timeout_seconds: int | None = None
        else:
            value = int(timeout_seconds)
            self.timeout_seconds = value if value > 0 else None

    def run(self, model: str, command: str, prompt: str) -> CLIExecutionResult:
        prompt_file: Path | None = None
        cmd = command
        try:
            if "{prompt_file}" in command:
                with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tmp:
                    tmp.write(prompt)
                    prompt_file = Path(tmp.name)
                cmd = command.format(prompt_file=str(prompt_file))

            proc = subprocess.run(
                shlex.split(cmd),
                input=None if "{prompt_file}" in command else prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            return CLIExecutionResult(
                model=model,
                ok=proc.returncode == 0,
                returncode=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                error="" if proc.returncode == 0 else f"non-zero exit ({proc.returncode})",
            )
        except subprocess.TimeoutExpired:
            timeout_label = (
                f"{self.timeout_seconds}s"
                if self.timeout_seconds is not None
                else "no-timeout"
            )
            return CLIExecutionResult(
                model=model,
                ok=False,
                returncode=-1,
                stdout="",
                stderr="",
                error=f"timeout after {timeout_label}",
            )
        except Exception as exc:
            return CLIExecutionResult(
                model=model,
                ok=False,
                returncode=-1,
                stdout="",
                stderr="",
                error=str(exc),
            )
        finally:
            if prompt_file and prompt_file.exists():
                prompt_file.unlink(missing_ok=True)


class ParallelRoundRunner:
    def __init__(self, executor: CLIModelExecutor | None = None):
        self.executor = executor or CLIModelExecutor()

    def run_round(self, prompt: str, codex_cmd: str, claude_cmd: str) -> dict[str, CLIExecutionResult]:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_codex = pool.submit(self.executor.run, "codex", codex_cmd, prompt)
            f_claude = pool.submit(self.executor.run, "claude", claude_cmd, prompt)
            return {
                "codex": f_codex.result(),
                "claude": f_claude.result(),
            }


def _extract_first_json_object(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_str = False
                continue

            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    raw = text[start : i + 1]
                    try:
                        val = json.loads(raw)
                    except json.JSONDecodeError:
                        break
                    if isinstance(val, dict):
                        return val
                    break
        start = text.find("{", start + 1)
    return None


def parse_model_verdict(model: str, output: str) -> ModelVerdict:
    data = _extract_first_json_object(output)
    if data is None:
        raise ValueError("No JSON object found in model output")

    evidence_items = data.get("evidence_locations", [])
    evidence: list[EvidenceLocation] = []
    if isinstance(evidence_items, list):
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            try:
                evidence.append(
                    EvidenceLocation(
                        file=str(item.get("file", "")),
                        line=int(item.get("line", 0)),
                        reason=str(item.get("reason", "")),
                    )
                )
            except Exception:
                continue

    confidence_raw = data.get("confidence", 0.0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    cvss_estimate: float | None
    cvss_raw = data.get("cvss_estimate")
    if cvss_raw is None:
        cvss_estimate = None
    else:
        try:
            cvss_estimate = float(cvss_raw)
        except (TypeError, ValueError):
            cvss_estimate = None

    vuln_raw = data.get("is_vulnerable")
    if isinstance(vuln_raw, bool):
        is_vulnerable = vuln_raw
    elif isinstance(vuln_raw, str):
        is_vulnerable = vuln_raw.lower() in {"true", "yes", "1", "vulnerable"}
    else:
        raise ValueError("Missing required boolean field 'is_vulnerable'")

    return ModelVerdict(
        model=model,
        is_vulnerable=is_vulnerable,
        summary=str(data.get("summary", "")),
        evidence_locations=evidence,
        cwe_id=str(data["cwe_id"]) if data.get("cwe_id") else None,
        cvss_estimate=cvss_estimate,
        reproduction_hypothesis=str(data.get("reproduction_hypothesis", "")),
        confidence=confidence,
        raw_output=output,
    )


def parse_trigger_plan(model: str, output: str) -> TriggerPlan:
    data = _extract_first_json_object(output)
    if data is None:
        raise ValueError("No JSON object found in model output")

    should_raw = data.get("should_attempt")
    if isinstance(should_raw, bool):
        should_attempt = should_raw
    elif isinstance(should_raw, str):
        should_attempt = should_raw.lower() in {"true", "yes", "1", "attempt"}
    else:
        raise ValueError("Missing required boolean field 'should_attempt'")

    trigger_kind = str(data.get("trigger_kind", "none")).strip().lower()
    if trigger_kind not in {"none", "command", "pov_stdin"}:
        trigger_kind = "none"

    execution_target = str(data.get("execution_target", "")).strip().lower()
    if execution_target and execution_target not in {"host_docker"}:
        execution_target = ""

    prepare_commands_raw = data.get("prepare_commands", [])
    prepare_commands: list[str] = []
    if isinstance(prepare_commands_raw, list):
        prepare_commands = [str(x).strip() for x in prepare_commands_raw if str(x).strip()]

    confidence_raw = data.get("confidence", 0.0)
    try:
        confidence = float(confidence_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    return TriggerPlan(
        model=model,
        should_attempt=should_attempt,
        trigger_kind=trigger_kind,
        execution_target=execution_target,
        prepare_commands=prepare_commands,
        verify_command=str(data.get("verify_command", "")),
        command=str(data.get("command", "")),
        pov_stdin=str(data.get("pov_stdin", "")),
        expected_signal=str(data.get("expected_signal", "")),
        confidence=confidence,
        rationale=str(data.get("rationale", "")),
        raw_output=output,
    )
