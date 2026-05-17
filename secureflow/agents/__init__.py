"""Agent nodes. Each agent is a callable `(state) -> partial_state_update`."""

from secureflow.agents.ai_discovery_agent import ai_discovery
from secureflow.agents.context_agent import collect_context
from secureflow.agents.decision_agent import decide as decision_node
from secureflow.agents.dependency_agent import dependency_scan
from secureflow.agents.enrichment_agent import enrich_findings
from secureflow.agents.exploitability_agent import exploitability
from secureflow.agents.iac_agent import iac_scan
from secureflow.agents.normalizer import normalize
from secureflow.agents.patch_agent import patch_generation
from secureflow.agents.reachability_agent import reachability_filter
from secureflow.agents.sast_agent import sast_scan
from secureflow.agents.secrets_agent import secrets_scan
from secureflow.agents.threat_mapping_agent import threat_map
from secureflow.agents.threat_model_agent import threat_model_delta

__all__ = [
    "ai_discovery",
    "collect_context",
    "decision_node",
    "dependency_scan",
    "enrich_findings",
    "exploitability",
    "iac_scan",
    "normalize",
    "patch_generation",
    "reachability_filter",
    "sast_scan",
    "secrets_scan",
    "threat_map",
    "threat_model_delta",
]
