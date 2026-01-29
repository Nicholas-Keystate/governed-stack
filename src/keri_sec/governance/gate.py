# -*- encoding: utf-8 -*-
"""
GovernanceGate - Fail-closed enforcement of cardinal rules on GAID operations.

Bridges the Tier enum (keri-sec attestation) to StrengthLevel (keri-governance)
and wraps GovernedCardinalChecker with opt-in, fail-closed semantics.

Usage:
    from keri_sec.governance import GovernanceGate, GovernanceViolation
    from keri_governance.cardinal import ArtifactType

    gate = GovernanceGate(artifact_type=ArtifactType.ALG)
    registry = AlgorithmDAIDRegistry(governance_gate=gate)

    # Operations are now checked against cardinal rules:
    # register() requires TEL_ANCHORED for algorithms
    # Without issuer_hab, strength is SAID_ONLY -> GovernanceViolation raised
"""

import logging
from typing import Any, Optional

from keri_governance.cardinal import ArtifactType, Operation
from keri_governance.primitives import StrengthLevel

from ..attestation import Tier
from .cardinal_checker_bridge import GovernedCardinalChecker, GovernedCheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tier <-> StrengthLevel mapping
# ---------------------------------------------------------------------------

# These enums have INVERTED ordinals:
#   Tier: TEL_ANCHORED=1 (strongest), KEL_ANCHORED=2, SAID_ONLY=3 (weakest)
#   StrengthLevel: ANY=0, SAID_ONLY=1, KEL_ANCHORED=2, TEL_ANCHORED=3 (strongest)

TIER_TO_STRENGTH = {
    Tier.TEL_ANCHORED: StrengthLevel.TEL_ANCHORED,
    Tier.KEL_ANCHORED: StrengthLevel.KEL_ANCHORED,
    Tier.SAID_ONLY: StrengthLevel.SAID_ONLY,
}

STRENGTH_TO_TIER = {v: k for k, v in TIER_TO_STRENGTH.items()}


def tier_to_strength(tier: Tier) -> StrengthLevel:
    """Map keri-sec Tier to keri-governance StrengthLevel."""
    return TIER_TO_STRENGTH[tier]


def strength_to_tier(strength: StrengthLevel) -> Optional[Tier]:
    """Map keri-governance StrengthLevel to keri-sec Tier. Returns None for ANY."""
    return STRENGTH_TO_TIER.get(strength)


def infer_strength(
    issuer_hab: Any = None,
    explicit_tier: Optional[Tier] = None,
) -> StrengthLevel:
    """
    Infer the StrengthLevel from attestation context.

    Priority:
    1. explicit_tier if provided -> mapped to StrengthLevel
    2. issuer_hab provided -> KEL_ANCHORED (signature + key state)
    3. Neither -> SAID_ONLY (content integrity only)
    """
    if explicit_tier is not None:
        return tier_to_strength(explicit_tier)
    if issuer_hab is not None:
        return StrengthLevel.KEL_ANCHORED
    return StrengthLevel.SAID_ONLY


# ---------------------------------------------------------------------------
# GovernanceViolation
# ---------------------------------------------------------------------------


class GovernanceViolation(Exception):
    """
    Raised when a GAID operation fails the cardinal governance check.

    Carries the GovernedCheckResult with full provenance (matrix GAID,
    SAID, version) for audit trail.
    """

    def __init__(self, result: GovernedCheckResult):
        self.result = result
        super().__init__(result.message)


# ---------------------------------------------------------------------------
# GovernanceGate
# ---------------------------------------------------------------------------


class GovernanceGate:
    """
    Opt-in enforcement gate for cardinal rules on GAID operations.

    When attached to a registry, every mutating operation (register, rotate,
    deprecate, revoke) is checked against the cardinal rule matrix before
    execution. If the operation's attestation strength is insufficient,
    GovernanceViolation is raised (fail-closed).

    Read-only operations (resolve, verify, list) are not gated.
    """

    def __init__(
        self,
        artifact_type: ArtifactType,
        checker: Optional[GovernedCardinalChecker] = None,
    ):
        self._artifact_type = artifact_type
        self._checker = checker or GovernedCardinalChecker()

    @property
    def artifact_type(self) -> ArtifactType:
        return self._artifact_type

    def enforce(
        self,
        operation: Operation,
        issuer_hab: Any = None,
        explicit_tier: Optional[Tier] = None,
    ) -> GovernedCheckResult:
        """
        Check and enforce a cardinal rule for an operation.

        Args:
            operation: The lifecycle operation being performed
            issuer_hab: The issuer hab (used to infer strength if no explicit_tier)
            explicit_tier: Override tier if caller knows their attestation level

        Returns:
            GovernedCheckResult with matrix provenance

        Raises:
            GovernanceViolation: If actual strength < required strength
        """
        actual_strength = infer_strength(issuer_hab, explicit_tier)
        result = self._checker.check(
            self._artifact_type, operation, actual_strength,
        )

        if not result.allowed:
            logger.warning(
                f"Governance violation: {self._artifact_type.value}:{operation.value} "
                f"requires stronger attestation ({result.message})"
            )
            raise GovernanceViolation(result)

        return result
