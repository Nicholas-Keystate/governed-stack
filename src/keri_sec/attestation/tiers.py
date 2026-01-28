# -*- encoding: utf-8 -*-
"""
Attestation Tiers - Graduated trust levels for GAID.

Three tiers based on trust requirements and cost:
- Tier 1: TEL-Anchored (highest trust, highest cost)
- Tier 2: Signed-Only (medium trust, medium cost)
- Tier 3: SAID-Only (integrity only, lowest cost)

Usage:
    from keri_sec.attestation import Tier, create_attestation

    # High trust: production verification
    attestation = create_attestation(
        tier=Tier.TEL_ANCHORED,
        content={"verified": True, "stack_said": "ESAID..."},
        issuer_hab=session_hab,
        schema_said=VERIFICATION_SCHEMA_SAID,
    )

    # Low cost: internal computation
    attestation = create_attestation(
        tier=Tier.SAID_ONLY,
        content={"result": True},
    )
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class Tier(Enum):
    """
    Attestation tier levels.

    KERI Principle: Signatures without KEL context are not verifiable.
    - TEL_ANCHORED: Full verifiability (signature → KEL → TEL)
    - KEL_ANCHORED: Signature anchored in KEL (no credential, but verifiable)
    - SAID_ONLY: Content integrity only (no authority claim)

    NOTE: There is no "signed-only" tier because a signature without
    KEL anchoring violates KERI's end-to-end verifiability principle.
    If you need to attest authority, use TEL_ANCHORED or KEL_ANCHORED.
    If you only need integrity, use SAID_ONLY.
    """
    TEL_ANCHORED = 1  # Full credential, TEL entry (highest trust)
    KEL_ANCHORED = 2  # Signature with KEL seal (medium trust, verifiable)
    SAID_ONLY = 3     # Content hash only (integrity, no authority)


@dataclass
class Attestation:
    """An attestation at any tier."""
    tier: Tier
    content_said: str
    content: Dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Tier 1 & 2: signature
    signature: Optional[str] = None
    signer_aid: Optional[str] = None

    # Tier 1 only: credential
    credential_said: Optional[str] = None
    registry_said: Optional[str] = None

    # KEL anchoring (Tier 2)
    kel_seal: Optional[str] = None  # Seal digest anchoring in KEL
    kel_sn: Optional[int] = None    # Sequence number of anchoring event

    @property
    def is_tel_anchored(self) -> bool:
        return self.tier == Tier.TEL_ANCHORED and self.credential_said is not None

    @property
    def is_kel_anchored(self) -> bool:
        return self.tier == Tier.KEL_ANCHORED and self.kel_seal is not None

    @property
    def is_verifiable(self) -> bool:
        """True if this attestation can be verified against KEL/TEL."""
        return self.is_tel_anchored or self.is_kel_anchored

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage."""
        return {
            "tier": self.tier.value,
            "content_said": self.content_said,
            "content": self.content,
            "created_at": self.created_at,
            "signature": self.signature,
            "signer_aid": self.signer_aid,
            "credential_said": self.credential_said,
            "registry_said": self.registry_said,
            "kel_seal": self.kel_seal,
            "kel_sn": self.kel_sn,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attestation":
        """Deserialize from storage."""
        return cls(
            tier=Tier(data["tier"]),
            content_said=data["content_said"],
            content=data["content"],
            created_at=data.get("created_at", ""),
            signature=data.get("signature"),
            signer_aid=data.get("signer_aid"),
            credential_said=data.get("credential_said"),
            registry_said=data.get("registry_said"),
            kel_seal=data.get("kel_seal"),
            kel_sn=data.get("kel_sn"),
        )

    def storage_size(self) -> int:
        """Estimate storage size in bytes."""
        return len(json.dumps(self.to_dict()))


def compute_said(content: Any) -> str:
    """Compute SAID for content.

    Uses Diger (not Saider) because we're hashing arbitrary JSON content,
    not Self-Addressing Data with a 'd' field placeholder.
    """
    try:
        from keri.core.coring import Diger, MtrDex
        canonical = json.dumps(content, sort_keys=True, separators=(',', ':'))
        return Diger(ser=canonical.encode(), code=MtrDex.Blake3_256).qb64
    except ImportError:
        # Fallback for testing without keripy
        import hashlib
        canonical = json.dumps(content, sort_keys=True, separators=(',', ':'))
        digest = hashlib.blake2b(canonical.encode(), digest_size=32).digest()
        import base64
        return "E" + base64.urlsafe_b64encode(digest).decode().rstrip("=")


def create_attestation(
    tier: Tier,
    content: Dict[str, Any],
    issuer_hab: Any = None,
    schema_said: Optional[str] = None,
    credential_service: Any = None,
) -> Attestation:
    """
    Create an attestation at the specified tier.

    Args:
        tier: Attestation tier (TEL_ANCHORED, KEL_ANCHORED, SAID_ONLY)
        content: Content to attest
        issuer_hab: Issuer's Hab (required for TEL_ANCHORED & KEL_ANCHORED)
        schema_said: Schema SAID (required for TEL_ANCHORED)
        credential_service: CredentialService (required for TEL_ANCHORED)

    Returns:
        Attestation object

    Note:
        There is no "SIGNED_ONLY" tier because a signature without KEL
        anchoring violates KERI's end-to-end verifiability principle.
        Use KEL_ANCHORED for verifiable signatures without TEL overhead.
    """
    content_said = compute_said(content)

    attestation = Attestation(
        tier=tier,
        content_said=content_said,
        content=content,
    )

    if tier == Tier.SAID_ONLY:
        # Just the content hash - no signature, no authority claim
        return attestation

    if issuer_hab is None:
        raise ValueError(f"issuer_hab required for {tier.name}")

    # Sign the content
    try:
        canonical = json.dumps(content, sort_keys=True, separators=(',', ':'))
        sig = issuer_hab.sign(ser=canonical.encode())
        attestation.signature = sig[0].qb64 if sig else None
        attestation.signer_aid = issuer_hab.pre
    except Exception as e:
        logger.warning(f"Signing failed: {e}")

    if tier == Tier.KEL_ANCHORED:
        # Anchor in KEL via interaction event with seal
        # This makes the signature verifiable against key state
        try:
            from keri.core import eventing, coring

            # Create seal linking to content SAID
            seal = {
                "i": content_said,  # Content SAID
                "s": "0",           # Sequence (first attestation of this content)
                "d": content_said,  # Digest
            }

            # Anchor seal in KEL via interaction event
            issuer_hab.interact(data=[seal])

            # Record the anchoring info
            attestation.kel_seal = content_said
            attestation.kel_sn = issuer_hab.kever.sner.num

            logger.debug(f"KEL-anchored attestation at sn={attestation.kel_sn}")
        except Exception as e:
            logger.warning(f"KEL anchoring failed: {e}, attestation not verifiable")

        return attestation

    # TEL-anchored: issue credential
    if credential_service is None or schema_said is None:
        raise ValueError("credential_service and schema_said required for TEL_ANCHORED")

    try:
        cred_said = credential_service.issue_credential(
            schema_said=schema_said,
            issuer_hab=issuer_hab,
            attributes={
                "d": "",  # Placeholder
                "dt": attestation.created_at,
                "contentSaid": content_said,
                **content,
            },
        )
        attestation.credential_said = cred_said
        attestation.registry_said = getattr(credential_service, 'registry_said', None)
    except Exception as e:
        logger.warning(f"Credential issuance failed: {e}, falling back to KEL-anchored")
        attestation.tier = Tier.KEL_ANCHORED

    return attestation


# Storage overhead estimates (verified via benchmark 2026-01-26)
# Note: These are FIXED overhead values, independent of content size.
# For small content (~30 bytes), this adds ~9x overhead.
# For large content (~8KB), this adds ~3% overhead.
OVERHEAD_ESTIMATES = {
    Tier.TEL_ANCHORED: {
        "attestation_bytes": 500,    # JSON serialized attestation
        "tel_entry_bytes": 200,      # TEL registry entry
        "credential_bytes": 800,     # Full ACDC credential
        "kel_entry_bytes": 150,      # Interaction event in KEL
        "total_estimate": 1650,
    },
    Tier.KEL_ANCHORED: {
        "attestation_bytes": 400,    # JSON with signature (~88 byte Ed25519)
        "tel_entry_bytes": 0,
        "credential_bytes": 0,
        "kel_entry_bytes": 150,      # Interaction event in KEL
        "total_estimate": 550,
    },
    Tier.SAID_ONLY: {
        "attestation_bytes": 260,    # JSON without signature (verified: ~259 fixed)
        "tel_entry_bytes": 0,
        "credential_bytes": 0,
        "kel_entry_bytes": 0,
        "total_estimate": 260,       # Updated from 200 based on benchmark
    },
}


def estimate_overhead(tier: Tier, count: int = 1) -> Dict[str, int]:
    """Estimate storage overhead for attestations."""
    estimates = OVERHEAD_ESTIMATES[tier].copy()
    estimates["count"] = count
    estimates["total"] = estimates["total_estimate"] * count
    return estimates
