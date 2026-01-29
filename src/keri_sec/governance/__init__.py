# -*- encoding: utf-8 -*-
"""
Governance Subpackage - GAID lifecycle for governance constructs.

Currently provides:
- CardinalRuleSet GAID: Content-addressable, versionable, auditable
  governance of the artifact×operation→strength policy matrix.
"""

from .cardinal_gaid import (
    CardinalRuleSetStatus,
    CardinalRuleSetGovernanceRules,
    CellChange,
    DeprecationNotice,
    CardinalRuleSetVersion,
    CardinalRuleSetGAID,
    VerificationResult,
    CardinalRuleSetRegistry,
    serialize_ruleset,
    compute_matrix_said,
    compute_diff,
    get_cardinal_ruleset_registry,
    reset_cardinal_ruleset_registry,
)

from .cardinal_checker_bridge import (
    GovernedCheckResult,
    GovernedCardinalChecker,
)

__all__ = [
    # Cardinal GAID
    "CardinalRuleSetStatus",
    "CardinalRuleSetGovernanceRules",
    "CellChange",
    "DeprecationNotice",
    "CardinalRuleSetVersion",
    "CardinalRuleSetGAID",
    "VerificationResult",
    "CardinalRuleSetRegistry",
    "serialize_ruleset",
    "compute_matrix_said",
    "compute_diff",
    "get_cardinal_ruleset_registry",
    "reset_cardinal_ruleset_registry",
    # Checker Bridge
    "GovernedCheckResult",
    "GovernedCardinalChecker",
]
