# -*- encoding: utf-8 -*-
"""
GovernedCardinalChecker - Bridge between CardinalChecker and GAID lifecycle.

Resolves the active cardinal ruleset from the GAID registry, delegates
to CardinalChecker, and stamps provenance (GAID, SAID, version) onto
the check result.

Usage:
    from keri_sec.governance import GovernedCardinalChecker

    checker = GovernedCardinalChecker()
    result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
    assert result.matrix_gaid  # provenance stamped
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional

from keri_governance.cardinal import (
    ArtifactType,
    CardinalCheckResult,
    CardinalChecker,
    Operation,
)
from keri_governance.primitives import StrengthLevel

from .cardinal_gaid import (
    CardinalRuleSetGAID,
    CardinalRuleSetRegistry,
    get_cardinal_ruleset_registry,
)

logger = logging.getLogger(__name__)


@dataclass
class GovernedCheckResult:
    """
    Wraps CardinalCheckResult with GAID provenance.

    Adds matrix_gaid, matrix_said, and matrix_version so that every
    governance check is traceable to a specific, content-addressed
    version of the cardinal rule matrix.
    """
    check_result: CardinalCheckResult
    matrix_gaid: str = ""
    matrix_said: str = ""
    matrix_version: str = ""

    @property
    def allowed(self) -> bool:
        return self.check_result.allowed

    @property
    def message(self) -> str:
        return self.check_result.message

    def to_dict(self) -> dict:
        d = self.check_result.to_dict()
        d["matrix_gaid"] = self.matrix_gaid
        d["matrix_said"] = self.matrix_said
        d["matrix_version"] = self.matrix_version
        return d


class GovernedCardinalChecker:
    """
    Cardinal checker backed by a GAID-governed ruleset.

    Resolves the active ruleset from the registry, wraps CardinalChecker,
    and stamps provenance onto results.
    """

    def __init__(
        self,
        registry: Optional[CardinalRuleSetRegistry] = None,
        gaid_name: str = "cardinal-default",
    ):
        """
        Args:
            registry: Registry to resolve from (defaults to singleton)
            gaid_name: Name or GAID of the ruleset to use
        """
        self._registry = registry or get_cardinal_ruleset_registry()
        self._gaid_name = gaid_name

    def _resolve(self) -> CardinalRuleSetGAID:
        gaid_obj = self._registry.resolve(self._gaid_name)
        if gaid_obj is None:
            raise ValueError(f"Cardinal ruleset not found: {self._gaid_name}")
        return gaid_obj

    def check(
        self,
        artifact_type: ArtifactType,
        operation: Operation,
        actual_strength: StrengthLevel,
    ) -> GovernedCheckResult:
        """
        Check an operation against the governed cardinal ruleset.

        Resolves the current ruleset from the GAID registry, delegates
        to CardinalChecker, and returns a provenance-stamped result.
        """
        gaid_obj = self._resolve()
        current = gaid_obj.current_version

        checker = CardinalChecker(current.ruleset)
        result = checker.check(artifact_type, operation, actual_strength)

        return GovernedCheckResult(
            check_result=result,
            matrix_gaid=gaid_obj.gaid,
            matrix_said=current.matrix_said,
            matrix_version=current.version,
        )

    def check_all(
        self,
        artifact_type: ArtifactType,
        actual_strength: StrengthLevel,
    ) -> Dict[Operation, GovernedCheckResult]:
        """
        Check all operations for an artifact type, with provenance.
        """
        gaid_obj = self._resolve()
        current = gaid_obj.current_version

        checker = CardinalChecker(current.ruleset)
        raw_results = checker.check_all(artifact_type, actual_strength)

        return {
            op: GovernedCheckResult(
                check_result=result,
                matrix_gaid=gaid_obj.gaid,
                matrix_said=current.matrix_said,
                matrix_version=current.version,
            )
            for op, result in raw_results.items()
        }
