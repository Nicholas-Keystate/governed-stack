# -*- encoding: utf-8 -*-
"""
CardinalRuleSet GAID - Governed Autonomic Identifier for the cardinal rule matrix.

Makes the 33-cell cardinal rule matrix (ArtifactType × Operation → StrengthLevel)
a first-class GAID:
- Content-addressable via SAID of the serialized matrix
- Versionable with append-only version chain and supersession
- Auditable with cell-level diffs and rationale
- Verifiable via SAID integrity check
- Meta-governed: rules constraining how the rules themselves evolve

The cardinal rule matrix lives in keri-governance (read-only dependency).
This module wraps it with GAID lifecycle management.

Usage:
    from keri_sec.governance import (
        get_cardinal_ruleset_registry,
        GovernedCardinalChecker,
    )

    registry = get_cardinal_ruleset_registry()
    gaid_obj = registry.resolve("cardinal-default")

    # Rotate a cell
    registry.rotate_cells(
        gaid=gaid_obj.gaid,
        changes=[CellChange(
            artifact_type=ArtifactType.ALG,
            operation=Operation.EXECUTE,
            previous_strength=StrengthLevel.SAID_ONLY,
            new_strength=StrengthLevel.KEL_ANCHORED,
            rationale="Algorithms now require key-state verification to execute",
        )],
        new_version="1.1.0",
    )
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from keri_governance.cardinal import (
    ArtifactType,
    CardinalRule,
    CardinalRuleSet,
    Operation,
    default_cardinal_rules,
)
from keri_governance.primitives import StrengthLevel

from ..attestation import Tier, Attestation, create_attestation, compute_said

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class CardinalRuleSetStatus(Enum):
    """Status of a cardinal ruleset GAID."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


# ---------------------------------------------------------------------------
# Serialization (deterministic, for SAID computation)
# ---------------------------------------------------------------------------


def serialize_ruleset(ruleset: CardinalRuleSet) -> dict:
    """
    Serialize a CardinalRuleSet to a canonical dict suitable for SAID computation.

    Format:
        {
            "matrix": {
                "alg:deprecate": {"min_strength": "KEL_ANCHORED", "rationale": "..."},
                ...
            },
            "cell_count": 33,
            "artifact_types": ["alg", "pkg", "pro", "run", "sch"],
            "operations": ["deprecate", "execute", "register", "resolve", "revoke", "rotate", "verify"]
        }

    All keys are sorted for deterministic serialization.
    """
    matrix = {}
    artifact_types = set()
    operations = set()

    for rule in ruleset.all_rules():
        key = f"{rule.artifact_type.value}:{rule.operation.value}"
        matrix[key] = {
            "min_strength": rule.min_strength.name,
            "rationale": rule.rationale,
        }
        artifact_types.add(rule.artifact_type.value)
        operations.add(rule.operation.value)

    return {
        "matrix": dict(sorted(matrix.items())),
        "cell_count": len(matrix),
        "artifact_types": sorted(artifact_types),
        "operations": sorted(operations),
    }


def compute_matrix_said(ruleset: CardinalRuleSet) -> str:
    """Compute SAID of a serialized CardinalRuleSet."""
    return compute_said(serialize_ruleset(ruleset))


# ---------------------------------------------------------------------------
# Cell-level diff
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CellChange:
    """A single cell change in the cardinal rule matrix."""
    artifact_type: ArtifactType
    operation: Operation
    previous_strength: StrengthLevel
    new_strength: StrengthLevel
    rationale: str = ""

    @property
    def cell_key(self) -> str:
        return f"{self.artifact_type.value}:{self.operation.value}"

    def to_dict(self) -> dict:
        return {
            "cell": self.cell_key,
            "previous": self.previous_strength.name,
            "new": self.new_strength.name,
            "rationale": self.rationale,
        }


def compute_diff(old: CardinalRuleSet, new: CardinalRuleSet) -> List[CellChange]:
    """
    Compute cell-level diff between two CardinalRuleSets.

    Returns list of CellChange for cells that differ in min_strength.
    """
    changes = []
    # Check all cells in old
    for rule in old.all_rules():
        new_rule = new.get(rule.artifact_type, rule.operation)
        if new_rule is None:
            # Cell removed
            changes.append(CellChange(
                artifact_type=rule.artifact_type,
                operation=rule.operation,
                previous_strength=rule.min_strength,
                new_strength=StrengthLevel.ANY,
                rationale="Cell removed",
            ))
        elif new_rule.min_strength != rule.min_strength:
            changes.append(CellChange(
                artifact_type=rule.artifact_type,
                operation=rule.operation,
                previous_strength=rule.min_strength,
                new_strength=new_rule.min_strength,
                rationale=new_rule.rationale,
            ))
    # Check for added cells
    for rule in new.all_rules():
        old_rule = old.get(rule.artifact_type, rule.operation)
        if old_rule is None:
            changes.append(CellChange(
                artifact_type=rule.artifact_type,
                operation=rule.operation,
                previous_strength=StrengthLevel.ANY,
                new_strength=rule.min_strength,
                rationale=rule.rationale,
            ))
    return changes


# ---------------------------------------------------------------------------
# Meta-governance rules
# ---------------------------------------------------------------------------


@dataclass
class CardinalRuleSetGovernanceRules:
    """
    Meta-governance: rules constraining how the cardinal rules themselves evolve.

    These are the governance rules FOR the governance rules.
    """
    min_rotation_strength: StrengthLevel = StrengthLevel.TEL_ANCHORED
    require_rationale: bool = True
    max_cells_per_rotation: Optional[int] = None
    allowed_strength_directions: str = "any"  # "any", "monotonic_up", "monotonic_down"

    def to_dict(self) -> dict:
        d: Dict[str, Any] = {
            "min_rotation_strength": self.min_rotation_strength.name,
            "require_rationale": self.require_rationale,
            "allowed_strength_directions": self.allowed_strength_directions,
        }
        if self.max_cells_per_rotation is not None:
            d["max_cells_per_rotation"] = self.max_cells_per_rotation
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "CardinalRuleSetGovernanceRules":
        return cls(
            min_rotation_strength=StrengthLevel[data.get("min_rotation_strength", "TEL_ANCHORED")],
            require_rationale=data.get("require_rationale", True),
            max_cells_per_rotation=data.get("max_cells_per_rotation"),
            allowed_strength_directions=data.get("allowed_strength_directions", "any"),
        )


# ---------------------------------------------------------------------------
# Deprecation
# ---------------------------------------------------------------------------


@dataclass
class DeprecationNotice:
    """Deprecation details for a cardinal ruleset GAID."""
    reason: str
    successor_gaid: Optional[str] = None
    migration_deadline: Optional[str] = None


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


@dataclass
class CardinalRuleSetVersion:
    """A specific version of the cardinal rule matrix."""
    sequence: int  # 0-based, append-only
    version: str  # Semantic version string
    matrix_said: str
    ruleset: CardinalRuleSet
    governance_rules: CardinalRuleSetGovernanceRules
    changes: List[CellChange] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation: Optional[Attestation] = None


# ---------------------------------------------------------------------------
# GAID
# ---------------------------------------------------------------------------


@dataclass
class CardinalRuleSetGAID:
    """
    A governed cardinal ruleset with GAID identity.

    The GAID remains stable across matrix rotations.
    Each rotation adds a CardinalRuleSetVersion to the history.
    """
    gaid: str  # Stable identifier (computed from inception)
    name: str
    status: CardinalRuleSetStatus = CardinalRuleSetStatus.ACTIVE
    deprecation: Optional[DeprecationNotice] = None
    versions: List[CardinalRuleSetVersion] = field(default_factory=list)
    current_version_index: int = 0

    @property
    def current_version(self) -> Optional[CardinalRuleSetVersion]:
        if self.versions:
            return self.versions[self.current_version_index]
        return None

    @property
    def current_ruleset(self) -> Optional[CardinalRuleSet]:
        if self.current_version:
            return self.current_version.ruleset
        return None

    @property
    def current_governance_rules(self) -> Optional[CardinalRuleSetGovernanceRules]:
        if self.current_version:
            return self.current_version.governance_rules
        return None

    @property
    def is_deprecated(self) -> bool:
        return self.status in (
            CardinalRuleSetStatus.DEPRECATED,
            CardinalRuleSetStatus.SUPERSEDED,
        )

    def to_dict(self) -> dict:
        return {
            "gaid": self.gaid,
            "name": self.name,
            "status": self.status.value,
            "version_count": len(self.versions),
            "current_version": self.current_version.version if self.current_version else None,
            "current_matrix_said": self.current_version.matrix_said if self.current_version else None,
        }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Result of verifying a cardinal ruleset GAID."""
    verified: bool
    gaid: str
    expected_said: str = ""
    actual_said: str = ""
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "gaid": self.gaid,
            "expected_said": self.expected_said,
            "actual_said": self.actual_said,
            "violations": self.violations,
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class CardinalRuleSetRegistry:
    """
    Registry of governed cardinal rulesets.

    Supports:
    - Registration with computed GAID
    - Cell rotation (append-only version chain)
    - Meta-governance enforcement
    - SAID integrity verification
    - Deprecation/supersession
    """

    def __init__(self):
        self._rulesets: Dict[str, CardinalRuleSetGAID] = {}  # gaid -> GAID obj
        self._by_name: Dict[str, str] = {}  # name -> gaid
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        ruleset: CardinalRuleSet,
        governance_rules: Optional[CardinalRuleSetGovernanceRules] = None,
        version: str = "1.0.0",
        issuer_hab: Any = None,
    ) -> CardinalRuleSetGAID:
        """
        Register a new governed cardinal ruleset, creating its GAID.

        Args:
            name: Ruleset name (e.g., "cardinal-default")
            ruleset: The CardinalRuleSet to govern
            governance_rules: Meta-governance rules (defaults provided)
            version: Initial version string
            issuer_hab: Issuer for attestation

        Returns:
            Registered CardinalRuleSetGAID
        """
        rules = governance_rules or CardinalRuleSetGovernanceRules()
        matrix_said = compute_matrix_said(ruleset)

        # GAID from inception data
        inception = {
            "name": name,
            "initial_matrix_said": matrix_said,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        gaid = compute_said(inception)

        initial_version = CardinalRuleSetVersion(
            sequence=0,
            version=version,
            matrix_said=matrix_said,
            ruleset=ruleset,
            governance_rules=rules,
        )

        if issuer_hab:
            try:
                initial_version.attestation = create_attestation(
                    tier=Tier.SAID_ONLY,
                    content={
                        "event": "cardinal_ruleset_registration",
                        "gaid": gaid,
                        "name": name,
                        "version": version,
                        "matrix_said": matrix_said,
                        "cell_count": len(ruleset),
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Attestation failed: {e}")

        gaid_obj = CardinalRuleSetGAID(
            gaid=gaid,
            name=name,
            versions=[initial_version],
        )

        with self._lock:
            self._rulesets[gaid] = gaid_obj
            self._by_name[name] = gaid

        logger.info(f"Registered cardinal ruleset GAID: {name} -> {gaid[:16]}...")
        return gaid_obj

    def resolve(self, identifier: str) -> Optional[CardinalRuleSetGAID]:
        """
        Resolve by GAID, GAID prefix, or name.
        """
        with self._lock:
            if identifier in self._rulesets:
                return self._rulesets[identifier]
            for gaid, obj in self._rulesets.items():
                if gaid.startswith(identifier):
                    return obj
            if identifier in self._by_name:
                return self._rulesets.get(self._by_name[identifier])
        return None

    def rotate(
        self,
        gaid: str,
        new_ruleset: CardinalRuleSet,
        new_version: str,
        new_governance_rules: Optional[CardinalRuleSetGovernanceRules] = None,
        issuer_hab: Any = None,
    ) -> CardinalRuleSetVersion:
        """
        Rotate to a completely new ruleset.

        For targeted cell changes, prefer rotate_cells().
        """
        gaid_obj = self.resolve(gaid)
        if gaid_obj is None:
            raise ValueError(f"Cardinal ruleset not found: {gaid}")

        old_ruleset = gaid_obj.current_ruleset
        gov_rules = new_governance_rules or gaid_obj.current_governance_rules or CardinalRuleSetGovernanceRules()

        changes = compute_diff(old_ruleset, new_ruleset) if old_ruleset else []
        self._validate_rotation(gov_rules, changes)

        matrix_said = compute_matrix_said(new_ruleset)
        new_ver = CardinalRuleSetVersion(
            sequence=len(gaid_obj.versions),
            version=new_version,
            matrix_said=matrix_said,
            ruleset=new_ruleset,
            governance_rules=gov_rules,
            changes=changes,
        )

        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.SAID_ONLY,
                    content={
                        "event": "cardinal_ruleset_rotation",
                        "gaid": gaid_obj.gaid,
                        "previous_version": gaid_obj.current_version.version,
                        "new_version": new_version,
                        "previous_matrix_said": gaid_obj.current_version.matrix_said,
                        "new_matrix_said": matrix_said,
                        "changes": [c.to_dict() for c in changes],
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Rotation attestation failed: {e}")

        with self._lock:
            gaid_obj.versions.append(new_ver)
            gaid_obj.current_version_index = len(gaid_obj.versions) - 1

        logger.info(
            f"Rotated {gaid_obj.name}: {gaid_obj.versions[-2].version} -> {new_version} "
            f"({len(changes)} cell changes)"
        )
        return new_ver

    def rotate_cells(
        self,
        gaid: str,
        changes: List[CellChange],
        new_version: str,
        new_governance_rules: Optional[CardinalRuleSetGovernanceRules] = None,
        issuer_hab: Any = None,
    ) -> CardinalRuleSetVersion:
        """
        Rotate specific cells in the cardinal matrix.

        Applies cell changes to the current ruleset and creates a new version.
        This is the preferred method for targeted policy adjustments.
        """
        gaid_obj = self.resolve(gaid)
        if gaid_obj is None:
            raise ValueError(f"Cardinal ruleset not found: {gaid}")

        current = gaid_obj.current_ruleset
        if current is None:
            raise ValueError("No current ruleset to rotate from")

        gov_rules = new_governance_rules or gaid_obj.current_governance_rules or CardinalRuleSetGovernanceRules()
        self._validate_rotation(gov_rules, changes)

        # Build new ruleset with applied changes
        new_rules = list(current.all_rules())
        change_map = {(c.artifact_type, c.operation): c for c in changes}

        updated_rules = []
        for rule in new_rules:
            key = (rule.artifact_type, rule.operation)
            if key in change_map:
                change = change_map.pop(key)
                updated_rules.append(CardinalRule(
                    artifact_type=rule.artifact_type,
                    operation=rule.operation,
                    min_strength=change.new_strength,
                    rationale=change.rationale or rule.rationale,
                ))
            else:
                updated_rules.append(rule)

        # Add any new cells from changes that didn't match existing rules
        for change in change_map.values():
            updated_rules.append(CardinalRule(
                artifact_type=change.artifact_type,
                operation=change.operation,
                min_strength=change.new_strength,
                rationale=change.rationale,
            ))

        new_ruleset = CardinalRuleSet(updated_rules)
        matrix_said = compute_matrix_said(new_ruleset)

        new_ver = CardinalRuleSetVersion(
            sequence=len(gaid_obj.versions),
            version=new_version,
            matrix_said=matrix_said,
            ruleset=new_ruleset,
            governance_rules=gov_rules,
            changes=changes,
        )

        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.SAID_ONLY,
                    content={
                        "event": "cardinal_ruleset_cell_rotation",
                        "gaid": gaid_obj.gaid,
                        "new_version": new_version,
                        "changes": [c.to_dict() for c in changes],
                        "new_matrix_said": matrix_said,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Cell rotation attestation failed: {e}")

        with self._lock:
            gaid_obj.versions.append(new_ver)
            gaid_obj.current_version_index = len(gaid_obj.versions) - 1

        logger.info(
            f"Cell rotation on {gaid_obj.name}: {new_version} "
            f"({len(changes)} cells changed)"
        )
        return new_ver

    def verify(self, gaid: str) -> VerificationResult:
        """
        Verify SAID integrity of a cardinal ruleset GAID.

        Recomputes the matrix SAID from the current ruleset and compares
        to the stored SAID.
        """
        gaid_obj = self.resolve(gaid)
        if gaid_obj is None:
            return VerificationResult(
                verified=False,
                gaid=gaid,
                violations=[f"Cardinal ruleset GAID not found: {gaid}"],
            )

        current = gaid_obj.current_version
        if current is None:
            return VerificationResult(
                verified=False,
                gaid=gaid_obj.gaid,
                violations=["No current version"],
            )

        actual_said = compute_matrix_said(current.ruleset)
        violations = []

        if actual_said != current.matrix_said:
            violations.append(
                f"Matrix SAID mismatch: expected {current.matrix_said[:16]}..., "
                f"got {actual_said[:16]}..."
            )

        return VerificationResult(
            verified=len(violations) == 0,
            gaid=gaid_obj.gaid,
            expected_said=current.matrix_said,
            actual_said=actual_said,
            violations=violations,
        )

    def deprecate(
        self,
        gaid: str,
        reason: str,
        successor_gaid: Optional[str] = None,
        migration_deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate a cardinal ruleset GAID."""
        gaid_obj = self.resolve(gaid)
        if gaid_obj is None:
            raise ValueError(f"Cardinal ruleset not found: {gaid}")

        with self._lock:
            gaid_obj.status = CardinalRuleSetStatus.DEPRECATED
            gaid_obj.deprecation = DeprecationNotice(
                reason=reason,
                successor_gaid=successor_gaid,
                migration_deadline=migration_deadline,
            )

        if issuer_hab:
            try:
                create_attestation(
                    tier=Tier.SAID_ONLY,
                    content={
                        "event": "cardinal_ruleset_deprecation",
                        "gaid": gaid_obj.gaid,
                        "name": gaid_obj.name,
                        "reason": reason,
                        "successor_gaid": successor_gaid,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Deprecation attestation failed: {e}")

        logger.warning(f"Deprecated cardinal ruleset: {gaid_obj.name} - {reason}")

    def list_rulesets(self, include_deprecated: bool = False) -> List[CardinalRuleSetGAID]:
        """List all registered cardinal rulesets."""
        with self._lock:
            rulesets = list(self._rulesets.values())
            if not include_deprecated:
                rulesets = [r for r in rulesets if not r.is_deprecated]
            return rulesets

    # --- Meta-governance validation ---

    def _validate_rotation(
        self,
        gov_rules: CardinalRuleSetGovernanceRules,
        changes: List[CellChange],
    ) -> None:
        """Validate a rotation against meta-governance rules."""
        if not changes:
            return

        if gov_rules.require_rationale:
            for change in changes:
                if not change.rationale.strip():
                    raise ValueError(
                        f"Rationale required for cell change: {change.cell_key}"
                    )

        if gov_rules.max_cells_per_rotation is not None:
            if len(changes) > gov_rules.max_cells_per_rotation:
                raise ValueError(
                    f"Too many cell changes: {len(changes)} > "
                    f"{gov_rules.max_cells_per_rotation} max"
                )

        if gov_rules.allowed_strength_directions == "monotonic_up":
            for change in changes:
                if change.new_strength < change.previous_strength:
                    raise ValueError(
                        f"Monotonic-up violation: {change.cell_key} "
                        f"{change.previous_strength.name} -> {change.new_strength.name}"
                    )
        elif gov_rules.allowed_strength_directions == "monotonic_down":
            for change in changes:
                if change.new_strength > change.previous_strength:
                    raise ValueError(
                        f"Monotonic-down violation: {change.cell_key} "
                        f"{change.previous_strength.name} -> {change.new_strength.name}"
                    )


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_registry: Optional[CardinalRuleSetRegistry] = None
_registry_lock = threading.Lock()


def get_cardinal_ruleset_registry() -> CardinalRuleSetRegistry:
    """
    Get the cardinal ruleset registry singleton.

    On first call, registers default_cardinal_rules() as genesis v1.0.0.
    """
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = CardinalRuleSetRegistry()
            _registry.register(
                name="cardinal-default",
                ruleset=default_cardinal_rules(),
                version="1.0.0",
            )
        return _registry


def reset_cardinal_ruleset_registry() -> None:
    """Reset the registry singleton (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
