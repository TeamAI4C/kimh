from src.v2.contracts import ValidationEvidence
from src.v2.validate import _resolve_multishot_status


def _e(verdict: str, positive: bool) -> ValidationEvidence:
    return ValidationEvidence(run_index=1, verdict=verdict, exit_code=0, is_positive=positive)


def test_multishot_confirmed_when_threshold_met() -> None:
    status = _resolve_multishot_status(
        consensus_vulnerable=True,
        evidences=[_e("crash", True), _e("crash", True)],
        required_positive=2,
    )
    assert status.value == "confirmed"


def test_multishot_probable_when_partial_positive() -> None:
    status = _resolve_multishot_status(
        consensus_vulnerable=True,
        evidences=[_e("crash", True), _e("pass", False)],
        required_positive=2,
    )
    assert status.value == "probable"


def test_multishot_needs_human_review_on_codex_failures() -> None:
    status = _resolve_multishot_status(
        consensus_vulnerable=True,
        evidences=[_e("codex_error", False)],
        required_positive=2,
    )
    assert status.value == "needs-human-review"


def test_multishot_rejected_when_clean_non_positive() -> None:
    status = _resolve_multishot_status(
        consensus_vulnerable=True,
        evidences=[_e("pass", False), _e("pass", False)],
        required_positive=2,
    )
    assert status.value == "rejected"
