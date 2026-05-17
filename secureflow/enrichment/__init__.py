"""External-API enrichment for findings.

Optional, best-effort, cached. If an API is down or rate-limited, the
enrichment is skipped and the finding keeps whatever it had from the
scanners / threat-mapping table.
"""

from secureflow.enrichment.cache import EnrichmentCache
from secureflow.enrichment.mitre_mapper import enrich_mitre
from secureflow.enrichment.nvd_client import NvdClient
from secureflow.enrichment.osv_client import OsvClient

__all__ = ["EnrichmentCache", "NvdClient", "OsvClient", "enrich_mitre"]
