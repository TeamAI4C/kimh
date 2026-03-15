import json

from src.v2.llm_cli import CLIModelExecutor, parse_trigger_plan


def test_parse_trigger_plan_command() -> None:
    raw = json.dumps(
        {
            "should_attempt": True,
            "execution_target": "host_docker",
            "prepare_commands": ["docker pull python:3.11"],
            "verify_command": "docker run --rm python:3.11 python -V",
            "trigger_kind": "command",
            "command": "pytest -q tests/test_x.py",
            "pov_stdin": "",
            "expected_signal": "test_failure",
            "confidence": 0.88,
            "rationale": "targeted test should fail",
        }
    )
    plan = parse_trigger_plan("codex", raw)
    assert plan.should_attempt is True
    assert plan.execution_target == "host_docker"
    assert plan.prepare_commands == ["docker pull python:3.11"]
    assert "docker run" in plan.verify_command
    assert plan.trigger_kind == "command"
    assert "pytest" in plan.command
    assert plan.confidence == 0.88


def test_parse_trigger_plan_accepts_embedded_json_text() -> None:
    raw = "noise\n" + json.dumps(
        {
            "should_attempt": "true",
            "trigger_kind": "pov_stdin",
            "pov_stdin": "AAAA",
            "command": "",
            "expected_signal": "asan",
            "confidence": 0.7,
            "rationale": "stdin trigger",
        }
    ) + "\nmore"
    plan = parse_trigger_plan("codex", raw)
    assert plan.should_attempt is True
    assert plan.trigger_kind == "pov_stdin"
    assert plan.pov_stdin == "AAAA"


def test_parse_trigger_plan_defaults_unknown_execution_target() -> None:
    raw = json.dumps(
        {
            "should_attempt": True,
            "execution_target": "invalid_target",
            "prepare_commands": "not-a-list",
            "verify_command": "echo ok",
            "trigger_kind": "command",
            "command": "echo legacy",
            "expected_signal": "ok",
            "confidence": 0.2,
            "rationale": "test",
        }
    )
    plan = parse_trigger_plan("codex", raw)
    assert plan.execution_target == ""
    assert plan.prepare_commands == []


def test_cli_executor_disables_timeout_for_non_positive(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured["timeout"] = kwargs.get("timeout")

        class Proc:
            returncode = 0
            stdout = '{"ok": true}'
            stderr = ""

        return Proc()

    monkeypatch.setattr("src.v2.llm_cli.subprocess.run", fake_run)
    executor = CLIModelExecutor(timeout_seconds=0)
    result = executor.run("codex", "echo ok", "prompt")

    assert result.ok is True
    assert captured["timeout"] is None


def test_cli_executor_keeps_positive_timeout(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured["timeout"] = kwargs.get("timeout")

        class Proc:
            returncode = 0
            stdout = '{"ok": true}'
            stderr = ""

        return Proc()

    monkeypatch.setattr("src.v2.llm_cli.subprocess.run", fake_run)
    executor = CLIModelExecutor(timeout_seconds=15)
    result = executor.run("codex", "echo ok", "prompt")

    assert result.ok is True
    assert captured["timeout"] == 15
