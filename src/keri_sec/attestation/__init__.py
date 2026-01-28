# -*- encoding: utf-8 -*-
"""
Attestation Module - GAID Trust Boundary Management.

Provides graduated attestation tiers and trust boundary decorators
for verifiable algorithm execution.

Usage:
    from keri_sec.attestation import (
        Tier,
        Attestation,
        create_attestation,
        trust_boundary,
        AttestableResult,
        estimate_overhead,
    )

    # Simple attestation
    attestation = create_attestation(
        tier=Tier.SAID_ONLY,
        content={"verified": True},
    )

    # Trust boundary decorator
    @trust_boundary(tier=Tier.TEL_ANCHORED, schema_said=SCHEMA)
    def verify_environment(profile, issuer_hab):
        return {"verified": True}

Credit:
- KERI attestation patterns: Samuel M. Smith
- Trust boundary concept: Security architecture principles
"""

from .tiers import (
    Tier,
    Attestation,
    create_attestation,
    compute_said,
    estimate_overhead,
    OVERHEAD_ESTIMATES,
)

from .boundaries import (
    trust_boundary,
    AttestableResult,
    bypass_attestation,
)

__all__ = [
    # Tiers
    "Tier",
    "Attestation",
    "create_attestation",
    "compute_said",
    "estimate_overhead",
    "OVERHEAD_ESTIMATES",
    # Boundaries
    "trust_boundary",
    "AttestableResult",
    "bypass_attestation",
]
