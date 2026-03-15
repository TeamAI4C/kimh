from src.v2.adjudicator import AdjudicationPolicy, adjudicate_round
from src.v2.contracts import EvidenceLocation, ModelVerdict


def _verdict(model: str, vulnerable: bool, confidence: float, with_evidence: bool = True) -> ModelVerdict:
    evidence = [EvidenceLocation(file="a.c", line=10, reason="tainted sink")] if with_evidence else []
    return ModelVerdict(
        model=model,
        is_vulnerable=vulnerable,
        summary="summary",
        evidence_locations=evidence,
        confidence=confidence,
    )


def test_consensus_when_models_agree_with_evidence_and_confidence() -> None:
    policy = AdjudicationPolicy(min_consensus_confidence=0.6, require_evidence=True)
    rec = adjudicate_round(
        round_index=1,
        codex=_verdict("codex", True, 0.8),
        claude=_verdict("claude", True, 0.9),
        policy=policy,
    )
    assert rec.decision.value == "consensus"
    assert rec.consensus_vulnerable is True


def test_dispute_when_models_disagree() -> None:
    policy = AdjudicationPolicy(min_consensus_confidence=0.6, require_evidence=True)
    rec = adjudicate_round(
        round_index=1,
        codex=_verdict("codex", True, 0.9),
        claude=_verdict("claude", False, 0.9),
        policy=policy,
    )
    assert rec.decision.value == "dispute"


def test_dispute_when_evidence_missing() -> None:
    policy = AdjudicationPolicy(min_consensus_confidence=0.6, require_evidence=True)
    rec = adjudicate_round(
        round_index=1,
        codex=_verdict("codex", True, 0.9, with_evidence=False),
        claude=_verdict("claude", True, 0.9, with_evidence=True),
        policy=policy,
    )
    assert rec.decision.value == "dispute"
    assert rec.evidence_sufficient is False
