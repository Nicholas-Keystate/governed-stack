# -*- encoding: utf-8 -*-
"""
OOBI Exchange for Cross-Org Credential Presentation

Handles Out-of-Band Introduction (OOBI) resolution for establishing
communication channels with external verifiers before credential presentation.

OOBI Flow:
    1. Receive verifier's OOBI URL
    2. Resolve OOBI to fetch verifier's KEL
    3. Verify verifier's key state
    4. Establish communication channel
    5. Present credentials via ESSR-wrapped IPEX

Reference: SPAC_Message.md Section "Relationship Discovery Protocols"

    "With KERI, we don't exchange public keys per se but AIDs that each has
    a verifiable key public key state."

Usage:
    from spac.oobi_exchange import OOBIExchangeDoer, create_oobi_exchanger

    # Create exchanger
    exchanger, pending, resolved = create_oobi_exchanger(hby)

    # Queue OOBI for resolution
    pending.push(OOBIRequest(
        oobi_url="http://verifier:5623/oobi/EVerifierAID.../witness/...",
        context_name="acme-verification",
    ))

    # Run with Doist
    doist.do(doers=[exchanger])

    # Check results
    while resolved:
        result = resolved.pull()
        if result.resolved:
            # Can now communicate with verifier
            ...
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from hio.base import doing
from hio.help import decking

if TYPE_CHECKING:
    from keri.app import habbing, oobiing

logger = logging.getLogger(__name__)


# =============================================================================
# OOBI Request/Response Types
# =============================================================================


class OOBIResolutionStatus(str, Enum):
    """Status of OOBI resolution."""

    PENDING = "pending"
    RESOLVING = "resolving"
    RESOLVED = "resolved"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class OOBIRequest:
    """
    Request to resolve an OOBI.

    Attributes:
        oobi_url: Full OOBI URL to resolve
        context_name: Optional relationship context for this verifier
        timeout_ms: Resolution timeout in milliseconds
        metadata: Optional metadata for tracking
    """

    oobi_url: str
    context_name: Optional[str] = None
    timeout_ms: int = 30000  # 30 seconds default
    metadata: Dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def parsed_url(self):
        """Parse the OOBI URL."""
        return urlparse(self.oobi_url)

    @property
    def verifier_aid_hint(self) -> Optional[str]:
        """
        Extract AID hint from OOBI URL if present.

        OOBI URLs typically have format:
        http://host:port/oobi/{aid}/witness/{witness_aid}
        """
        path_parts = self.parsed_url.path.strip("/").split("/")
        if len(path_parts) >= 2 and path_parts[0] == "oobi":
            return path_parts[1]
        return None


@dataclass
class OOBIResult:
    """
    Result of OOBI resolution.

    Attributes:
        request: Original request
        status: Resolution status
        verifier_aid: Resolved verifier AID (if successful)
        verifier_keystate: Key state info (if successful)
        error: Error message (if failed)
        resolved_at: When resolution completed
    """

    request: OOBIRequest
    status: OOBIResolutionStatus
    verifier_aid: Optional[str] = None
    verifier_keystate: Optional[Dict] = None
    witness_aids: List[str] = field(default_factory=list)
    error: Optional[str] = None
    resolved_at: Optional[datetime] = None

    @property
    def resolved(self) -> bool:
        """Check if resolution was successful."""
        return self.status == OOBIResolutionStatus.RESOLVED

    @property
    def can_communicate(self) -> bool:
        """Check if we can communicate with the verifier."""
        return self.resolved and self.verifier_aid is not None


# =============================================================================
# Endpoint Configuration
# =============================================================================


@dataclass
class EndpointConfig:
    """Configuration for a known verifier endpoint."""

    name: str
    oobi_template: str  # URL template with {aid}, {wit} placeholders
    description: str = ""
    trust_level: str = "unknown"  # high, medium, low, development, unknown
    metadata: Dict = field(default_factory=dict)

    def build_oobi_url(self, aid: str, witness: Optional[str] = None) -> str:
        """Build OOBI URL from template."""
        url = self.oobi_template.replace("{aid}", aid)
        if witness:
            url = url.replace("{wit}", witness)
        return url


@dataclass
class EndpointRegistry:
    """
    Registry of known verifier endpoints.

    Loaded from ~/.keri/cf/spac-endpoints.json
    """

    version: str = "1.0.0"
    endpoints: Dict[str, EndpointConfig] = field(default_factory=dict)
    default_witnesses: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "EndpointRegistry":
        """
        Load endpoint registry from config file.

        Args:
            config_path: Path to config file, defaults to ~/.keri/cf/spac-endpoints.json

        Returns:
            EndpointRegistry instance
        """
        if config_path is None:
            config_path = Path.home() / ".keri" / "cf" / "spac-endpoints.json"

        registry = cls()

        if not config_path.exists():
            logger.info(f"No endpoint config at {config_path}, using empty registry")
            return registry

        try:
            with open(config_path) as f:
                data = json.load(f)

            registry.version = data.get("version", "1.0.0")
            registry.default_witnesses = data.get("default_witnesses", [])

            for name, endpoint_data in data.get("endpoints", {}).items():
                registry.endpoints[name] = EndpointConfig(
                    name=name,
                    oobi_template=endpoint_data.get("oobi", ""),
                    description=endpoint_data.get("description", ""),
                    trust_level=endpoint_data.get("trust_level", "unknown"),
                    metadata=endpoint_data.get("metadata", {}),
                )

            logger.info(f"Loaded {len(registry.endpoints)} endpoints from {config_path}")

        except Exception as e:
            logger.error(f"Failed to load endpoint config: {e}")

        return registry

    def save(self, config_path: Optional[Path] = None):
        """Save endpoint registry to config file."""
        if config_path is None:
            config_path = Path.home() / ".keri" / "cf" / "spac-endpoints.json"

        config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "version": self.version,
            "endpoints": {
                name: {
                    "oobi": ep.oobi_template,
                    "description": ep.description,
                    "trust_level": ep.trust_level,
                    "metadata": ep.metadata,
                }
                for name, ep in self.endpoints.items()
            },
            "default_witnesses": self.default_witnesses,
        }

        with open(config_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved {len(self.endpoints)} endpoints to {config_path}")

    def get_endpoint(self, name: str) -> Optional[EndpointConfig]:
        """Get endpoint by name."""
        return self.endpoints.get(name)

    def add_endpoint(self, endpoint: EndpointConfig):
        """Add or update an endpoint."""
        self.endpoints[endpoint.name] = endpoint

    def list_endpoints(self, trust_level: Optional[str] = None) -> List[EndpointConfig]:
        """List endpoints, optionally filtered by trust level."""
        if trust_level:
            return [ep for ep in self.endpoints.values() if ep.trust_level == trust_level]
        return list(self.endpoints.values())


# =============================================================================
# OOBI Exchange Doer
# =============================================================================


class OOBIExchangeDoer(doing.DoDoer):
    """
    HIO Doer for OOBI resolution.

    Handles asynchronous resolution of OOBIs using keripy's Oobiery.

    Communication Pattern:
        pending_requests -> [OOBIExchangeDoer] -> resolved_results
                                              -> failed (logged)

    Features:
        - Asynchronous OOBI resolution
        - Timeout handling
        - Retry logic
        - Integration with ORI manager for relationship context

    Usage:
        pending = decking.Deck()
        resolved = decking.Deck()

        exchanger = OOBIExchangeDoer(
            hby=hby,
            oobiery=oobiery,
            pending_requests=pending,
            resolved_results=resolved,
        )

        # Queue requests
        pending.push(OOBIRequest(oobi_url="http://..."))

        # Run with Doist
        doist = doing.Doist(limit=60.0)
        doist.do(doers=[exchanger])
    """

    def __init__(
        self,
        hby: "habbing.Habery",
        oobiery: "oobiing.Oobiery",
        pending_requests: decking.Deck,
        resolved_results: decking.Deck,
        endpoint_registry: Optional[EndpointRegistry] = None,
        max_retries: int = 3,
        **kwa,
    ):
        """
        Initialize OOBI exchanger.

        Args:
            hby: Habery for key state access
            oobiery: keripy Oobiery for OOBI resolution
            pending_requests: Deck for incoming OOBI requests
            resolved_results: Deck for resolution results
            endpoint_registry: Optional pre-loaded endpoint registry
            max_retries: Maximum resolution retries
        """
        super().__init__(**kwa)

        self.hby = hby
        self.oobiery = oobiery
        self.pending_requests = pending_requests
        self.resolved_results = resolved_results
        self.endpoint_registry = endpoint_registry or EndpointRegistry.load()
        self.max_retries = max_retries

        # In-progress resolutions: oobi_url -> (request, attempt_count, start_time)
        self._resolving: Dict[str, tuple] = {}

        # Statistics
        self.stats = {
            "requests_received": 0,
            "resolutions_started": 0,
            "resolutions_succeeded": 0,
            "resolutions_failed": 0,
            "resolutions_timeout": 0,
        }

    def recur(self, tyme: float) -> bool:
        """
        Process OOBI resolution requests.

        Args:
            tyme: Current HIO time

        Returns:
            True to continue processing
        """
        # Process new requests
        while len(self.pending_requests) > 0:
            request = self.pending_requests.pull()
            self._start_resolution(request, tyme)

        # Check in-progress resolutions
        self._check_resolutions(tyme)

        return True

    def _start_resolution(self, request: OOBIRequest, tyme: float):
        """Start resolving an OOBI."""
        self.stats["requests_received"] += 1

        # Check if already resolving
        if request.oobi_url in self._resolving:
            logger.debug(f"Already resolving: {request.oobi_url}")
            return

        logger.info(f"Starting OOBI resolution: {request.oobi_url[:60]}...")

        # Queue to oobiery
        try:
            self.oobiery.oobis.append(dict(oobialias=request.context_name or "", url=request.oobi_url))
            self._resolving[request.oobi_url] = (request, 1, tyme)
            self.stats["resolutions_started"] += 1

        except Exception as e:
            logger.error(f"Failed to queue OOBI: {e}")
            self._complete_resolution(
                request,
                OOBIResolutionStatus.FAILED,
                error=str(e),
            )

    def _check_resolutions(self, tyme: float):
        """Check status of in-progress resolutions."""
        completed = []

        for oobi_url, (request, attempt, start_time) in self._resolving.items():
            # Check timeout
            elapsed_ms = (tyme - start_time) * 1000
            if elapsed_ms > request.timeout_ms:
                if attempt < self.max_retries:
                    # Retry
                    logger.warning(f"OOBI timeout, retrying ({attempt}/{self.max_retries}): {oobi_url[:40]}...")
                    self._resolving[oobi_url] = (request, attempt + 1, tyme)
                    self.oobiery.oobis.append(dict(oobialias=request.context_name or "", url=oobi_url))
                else:
                    # Max retries exceeded
                    completed.append(oobi_url)
                    self._complete_resolution(
                        request,
                        OOBIResolutionStatus.TIMEOUT,
                        error=f"Resolution timeout after {self.max_retries} attempts",
                    )
                    self.stats["resolutions_timeout"] += 1
                continue

            # Check if resolved (verifier's KEL now in our database)
            verifier_aid = request.verifier_aid_hint
            if verifier_aid:
                kever = self.hby.kevers.get(verifier_aid)
                if kever:
                    # Resolution successful
                    completed.append(oobi_url)
                    self._complete_resolution(
                        request,
                        OOBIResolutionStatus.RESOLVED,
                        verifier_aid=verifier_aid,
                        verifier_keystate={
                            "sn": kever.sner.num,
                            "dig": kever.serder.said if hasattr(kever, 'serder') else None,
                        },
                    )
                    self.stats["resolutions_succeeded"] += 1

        # Clean up completed
        for url in completed:
            del self._resolving[url]

    def _complete_resolution(
        self,
        request: OOBIRequest,
        status: OOBIResolutionStatus,
        verifier_aid: Optional[str] = None,
        verifier_keystate: Optional[Dict] = None,
        error: Optional[str] = None,
    ):
        """Complete a resolution and push result."""
        result = OOBIResult(
            request=request,
            status=status,
            verifier_aid=verifier_aid,
            verifier_keystate=verifier_keystate,
            error=error,
            resolved_at=datetime.now(timezone.utc),
        )

        self.resolved_results.push(result)

        if status == OOBIResolutionStatus.RESOLVED:
            logger.info(f"OOBI resolved: {verifier_aid[:16] if verifier_aid else 'unknown'}...")
        else:
            logger.warning(f"OOBI resolution {status.value}: {error or 'unknown error'}")

    def resolve_endpoint(self, endpoint_name: str, aid: str, witness: Optional[str] = None) -> bool:
        """
        Convenience method to resolve a known endpoint.

        Args:
            endpoint_name: Name in endpoint registry
            aid: AID to include in OOBI URL
            witness: Optional witness AID

        Returns:
            True if resolution queued successfully
        """
        endpoint = self.endpoint_registry.get_endpoint(endpoint_name)
        if not endpoint:
            logger.error(f"Unknown endpoint: {endpoint_name}")
            return False

        oobi_url = endpoint.build_oobi_url(aid, witness)

        request = OOBIRequest(
            oobi_url=oobi_url,
            context_name=endpoint_name,
            metadata={"trust_level": endpoint.trust_level},
        )

        self.pending_requests.push(request)
        return True

    def get_stats(self) -> Dict:
        """Get resolution statistics."""
        return {
            **self.stats,
            "currently_resolving": len(self._resolving),
            "known_endpoints": len(self.endpoint_registry.endpoints),
        }


# =============================================================================
# Factory Function
# =============================================================================


def create_oobi_exchanger(
    hby: "habbing.Habery",
    oobiery: "oobiing.Oobiery",
    endpoint_registry: Optional[EndpointRegistry] = None,
) -> tuple:
    """
    Factory function to create OOBI exchanger with dependencies.

    Args:
        hby: Habery instance
        oobiery: Oobiery instance
        endpoint_registry: Optional pre-loaded registry

    Returns:
        Tuple of (exchanger_doer, pending_deck, resolved_deck)
    """
    pending = decking.Deck()
    resolved = decking.Deck()

    exchanger = OOBIExchangeDoer(
        hby=hby,
        oobiery=oobiery,
        pending_requests=pending,
        resolved_results=resolved,
        endpoint_registry=endpoint_registry,
    )

    return exchanger, pending, resolved
