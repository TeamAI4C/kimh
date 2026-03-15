from src.v2.analyze import _filter_findings_by_primary_path


def _finding(path: str) -> dict:
    return {
        "rule_id": "py/path-injection",
        "chain": [{"file": path, "line": 10, "action": "source"}],
    }


def test_filters_when_primary_file_matches_test_glob() -> None:
    findings = [_finding("tests/test_demo.py"), _finding("app/main.py")]
    kept, excluded = _filter_findings_by_primary_path(findings, ["tests/**", "**/*_test.py"])
    assert len(kept) == 1
    assert kept[0]["chain"][0]["file"] == "app/main.py"
    assert len(excluded) == 1
    assert excluded[0][0]["chain"][0]["file"] == "tests/test_demo.py"


def test_keeps_when_primary_file_not_matched() -> None:
    findings = [_finding("src/service/handler.py")]
    kept, excluded = _filter_findings_by_primary_path(findings, ["tests/**", "test/**"])
    assert len(kept) == 1
    assert excluded == []
