"""Decision node — runs the deterministic policy engine."""

from __future__ import annotations

from secureflow.config import Config
from secureflow.policy import decide as policy_decide
from secureflow.utils.logging import get_logger

log = get_logger("agent.decision")


def decide(state: dict) -> dict:
    cfg = Config.model_validate(state.get("config") or {})
    findings = list(state.get("final_findings") or state.get("mapped_findings") or [])

    skipped = []
    for component, error in (state.get("scanner_errors") or {}).items():
        skipped.append(f"{component}: {error}")

    threat_model = list(state.get("threat_model_findings") or [])
    decision = policy_decide(
        findings,
        policy=cfg.policy,
        skipped_components=skipped,
        threat_model_findings=threat_model,
    )
    log.info(
        "decision: status=%s score=%d reasons=%d",
        decision.status, decision.risk_score, len(decision.reasons),
    )
    return {"decision": decision.model_dump()}
