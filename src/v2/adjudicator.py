from __future__ import annotations

from dataclasses import dataclass

from src.v2.contracts import AdjudicationDecision, AdjudicationRecord, ModelVerdict


@dataclass
class AdjudicationPolicy:
    min_consensus_confidence: float = 0.60
    require_evidence: bool = True


def adjudicate_round(
    round_index: int,
    codex: ModelVerdict | None,
    claude: ModelVerdict | None,
    policy: AdjudicationPolicy,
) -> AdjudicationRecord:
    if codex is None or claude is None:
        return AdjudicationRecord(
            round_index=round_index,
            decision=AdjudicationDecision.DISPUTE,
            reason="missing model response",
            evidence_sufficient=False,
            consensus_vulnerable=None,
            consensus_confidence=0.0,
            codex=codex,
            claude=claude,
        )

    if codex.is_vulnerable != claude.is_vulnerable:
        return AdjudicationRecord(
            round_index=round_index,
            decision=AdjudicationDecision.DISPUTE,
            reason="model disagreement on vulnerability existence",
            evidence_sufficient=False,
            consensus_vulnerable=None,
            consensus_confidence=0.0,
            codex=codex,
            claude=claude,
        )

    evidence_sufficient = True
    if policy.require_evidence:
        evidence_sufficient = bool(codex.evidence_locations) and bool(claude.evidence_locations)
        if not evidence_sufficient:
            return AdjudicationRecord(
                round_index=round_index,
                decision=AdjudicationDecision.DISPUTE,
                reason="insufficient evidence locations",
                evidence_sufficient=False,
                consensus_vulnerable=None,
                consensus_confidence=0.0,
                codex=codex,
                claude=claude,
            )

    confidence = (codex.confidence + claude.confidence) / 2.0
    if confidence < policy.min_consensus_confidence:
        return AdjudicationRecord(
            round_index=round_index,
            decision=AdjudicationDecision.DISPUTE,
            reason="consensus confidence below threshold",
            evidence_sufficient=evidence_sufficient,
            consensus_vulnerable=None,
            consensus_confidence=confidence,
            codex=codex,
            claude=claude,
        )

    return AdjudicationRecord(
        round_index=round_index,
        decision=AdjudicationDecision.CONSENSUS,
        reason="models agree with sufficient confidence and evidence",
        evidence_sufficient=evidence_sufficient,
        consensus_vulnerable=codex.is_vulnerable,
        consensus_confidence=confidence,
        codex=codex,
        claude=claude,
    )
