import json

from src.v2.llm_cli import parse_trigger_plan


def test_parse_trigger_plan_command() -> None:
    raw = json.dumps(
        {
            "should_attempt": True,
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
