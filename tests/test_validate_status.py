from src.v2.contracts import ValidationEvidence
from src.v2.validate import resolve_final_status


def _e(verdict: str, positive: bool) -> ValidationEvidence:
    return ValidationEvidence(
        run_index=1,
        verdict=verdict,
        exit_code=0,
        is_positive=positive,
    )


def test_confirmed_requires_all_positive_runs() -> None:
    status = resolve_final_status(
        final_decision="consensus",
        consensus_vulnerable=True,
        evidences=[_e("crash", True), _e("crash", True)],
        verify_runs=2,
    )
    assert status.value == "confirmed"


def test_probable_on_partial_positive() -> None:
    status = resolve_final_status(
        final_decision="consensus",
        consensus_vulnerable=True,
        evidences=[_e("crash", True), _e("pass", False)],
        verify_runs=2,
    )
    assert status.value == "probable"


def test_rejected_on_clean_non_positive_runs() -> None:
    status = resolve_final_status(
        final_decision="consensus",
        consensus_vulnerable=True,
        evidences=[_e("pass", False), _e("pass", False)],
        verify_runs=2,
    )
    assert status.value == "rejected"


def test_needs_human_review_on_unresolved_analysis() -> None:
    status = resolve_final_status(
        final_decision="needs-human-review",
        consensus_vulnerable=None,
        evidences=[],
        verify_runs=2,
    )
    assert status.value == "needs-human-review"
