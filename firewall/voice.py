"""Voice channel controls for agents that answer phone calls.

Cloned voices now pass voiceprint checks, so this module follows one rule:
a voice is never proof of identity. The gateway takes risk signals from
whatever voice stack the bank runs (a synthetic-speech detector, a liveness
check, STIR/SHAKEN caller ID attestation) and decides how far to trust the
call. Even a clean call can't move money without out-of-band confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VoiceSignals:
    synthetic_score: float          # 0..1 from a deepfake / synthetic speech detector
    liveness_passed: bool           # challenge-response or acoustic liveness
    caller_id_attestation: str | None  # STIR/SHAKEN level: "A", "B", "C" or None
    voiceprint_match: float | None = None  # logged for analytics, never used to authorize


@dataclass(frozen=True)
class VoiceRules:
    block_at: float = 0.85          # synthetic score that ends the call
    review_at: float = 0.5          # synthetic score that flags for review
    trusted_attestation: str = "A"
    step_up_for_money: bool = True  # money over voice always needs in-app confirmation

    @classmethod
    def from_dict(cls, d: dict | None) -> "VoiceRules":
        d = d or {}
        return cls(
            block_at=float(d.get("block_synthetic_score", 0.85)),
            review_at=float(d.get("review_synthetic_score", 0.5)),
            trusted_attestation=str(d.get("trusted_caller_id_attestation", "A")),
            step_up_for_money=bool(d.get("step_up_for_money_movement", True)),
        )


def assess(sig: VoiceSignals, rules: VoiceRules) -> tuple[str, str]:
    """Return (verdict, reason). Verdict is 'block', 'flag' or 'allow'."""
    vp = f" Voiceprint match {sig.voiceprint_match:.0%} was logged but does not count as identity." if sig.voiceprint_match is not None else ""
    if sig.synthetic_score >= rules.block_at:
        return "block", f"Synthetic voice detected (score {sig.synthetic_score:.2f}). Call ended and fraud team alerted.{vp}"
    problems = []
    if sig.synthetic_score >= rules.review_at:
        problems.append(f"possible synthetic voice (score {sig.synthetic_score:.2f})")
    if not sig.liveness_passed:
        problems.append("liveness check failed")
    if sig.caller_id_attestation != rules.trusted_attestation:
        problems.append(f"caller ID not fully verified (attestation {sig.caller_id_attestation or 'none'})")
    if problems:
        return "flag", "Caller treated as unverified: " + "; ".join(problems) + "." + vp
    return "allow", "Live human voice from a verified number." + vp
