# -*- encoding: utf-8 -*-
"""Tests for CardinalRuleSet GAID lifecycle."""

import pytest

from keri_governance.cardinal import (
    ArtifactType,
    CardinalRule,
    CardinalRuleSet,
    Operation,
    default_cardinal_rules,
)
from keri_governance.primitives import StrengthLevel

from keri_sec.governance.cardinal_gaid import (
    CardinalRuleSetGAID,
    CardinalRuleSetGovernanceRules,
    CardinalRuleSetRegistry,
    CardinalRuleSetStatus,
    CardinalRuleSetVersion,
    CellChange,
    VerificationResult,
    compute_diff,
    compute_matrix_said,
    get_cardinal_ruleset_registry,
    reset_cardinal_ruleset_registry,
    serialize_ruleset,
)
from keri_sec.governance.cardinal_checker_bridge import (
    GovernedCardinalChecker,
    GovernedCheckResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the singleton before each test."""
    reset_cardinal_ruleset_registry()
    yield
    reset_cardinal_ruleset_registry()


@pytest.fixture
def default_ruleset():
    return default_cardinal_rules()


@pytest.fixture
def registry():
    return CardinalRuleSetRegistry()


@pytest.fixture
def registered_gaid(registry, default_ruleset):
    return registry.register(
        name="test-cardinal",
        ruleset=default_ruleset,
        version="1.0.0",
    )


# ---------------------------------------------------------------------------
# TestSerialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Test deterministic serialization of cardinal rulesets."""

    def test_serialize_default_rules(self, default_ruleset):
        data = serialize_ruleset(default_ruleset)
        assert "matrix" in data
        assert data["cell_count"] == 33
        assert sorted(data["artifact_types"]) == ["alg", "pkg", "pro", "run", "sch"]
        assert "register" in data["operations"]

    def test_serialize_deterministic(self, default_ruleset):
        """Same ruleset serializes to identical output."""
        a = serialize_ruleset(default_ruleset)
        b = serialize_ruleset(default_ruleset)
        assert a == b

    def test_serialize_sorted_keys(self, default_ruleset):
        data = serialize_ruleset(default_ruleset)
        keys = list(data["matrix"].keys())
        assert keys == sorted(keys)

    def test_cell_values_have_strength_and_rationale(self, default_ruleset):
        data = serialize_ruleset(default_ruleset)
        for key, value in data["matrix"].items():
            assert "min_strength" in value
            assert "rationale" in value
            assert value["min_strength"] in [
                "ANY", "SAID_ONLY", "KEL_ANCHORED", "TEL_ANCHORED",
            ]


# ---------------------------------------------------------------------------
# TestGAIDStability
# ---------------------------------------------------------------------------


class TestGAIDStability:
    """Test that GAID and SAID computations are stable."""

    def test_matrix_said_stable(self, default_ruleset):
        said_1 = compute_matrix_said(default_ruleset)
        said_2 = compute_matrix_said(default_ruleset)
        assert said_1 == said_2

    def test_matrix_said_changes_with_content(self, default_ruleset):
        said_before = compute_matrix_said(default_ruleset)
        # Modify one cell
        default_ruleset.add(CardinalRule(
            ArtifactType.ALG, Operation.EXECUTE,
            StrengthLevel.TEL_ANCHORED,
            "Changed for test",
        ))
        said_after = compute_matrix_said(default_ruleset)
        assert said_before != said_after

    def test_gaid_stable_across_registrations(self):
        """Different registrations produce different GAIDs (inception includes timestamp)."""
        reg = CardinalRuleSetRegistry()
        g1 = reg.register("test-1", default_cardinal_rules(), version="1.0.0")
        g2 = reg.register("test-2", default_cardinal_rules(), version="1.0.0")
        assert g1.gaid != g2.gaid

    def test_gaid_is_content_addressed(self, registered_gaid):
        """GAID is a SAID (starts with 'E' for Blake3)."""
        assert registered_gaid.gaid.startswith("E")


# ---------------------------------------------------------------------------
# TestVersionChain
# ---------------------------------------------------------------------------


class TestVersionChain:
    """Test append-only version chain."""

    def test_initial_version(self, registered_gaid):
        assert len(registered_gaid.versions) == 1
        assert registered_gaid.current_version.sequence == 0
        assert registered_gaid.current_version.version == "1.0.0"

    def test_rotate_appends_version(self, registry, registered_gaid):
        new_ruleset = default_cardinal_rules()
        new_ruleset.add(CardinalRule(
            ArtifactType.ALG, Operation.EXECUTE,
            StrengthLevel.KEL_ANCHORED,
            "Upgraded for test",
        ))
        registry.rotate(
            gaid=registered_gaid.gaid,
            new_ruleset=new_ruleset,
            new_version="1.1.0",
        )
        assert len(registered_gaid.versions) == 2
        assert registered_gaid.current_version.version == "1.1.0"
        assert registered_gaid.current_version.sequence == 1

    def test_version_chain_immutable(self, registry, registered_gaid):
        """Earlier versions are preserved after rotation."""
        v0_said = registered_gaid.current_version.matrix_said

        new_ruleset = default_cardinal_rules()
        new_ruleset.add(CardinalRule(
            ArtifactType.ALG, Operation.EXECUTE,
            StrengthLevel.TEL_ANCHORED,
            "Changed",
        ))
        registry.rotate(
            gaid=registered_gaid.gaid,
            new_ruleset=new_ruleset,
            new_version="2.0.0",
        )

        assert registered_gaid.versions[0].matrix_said == v0_said
        assert registered_gaid.versions[1].matrix_said != v0_said


# ---------------------------------------------------------------------------
# TestCellRotation
# ---------------------------------------------------------------------------


class TestCellRotation:
    """Test targeted cell rotation."""

    def test_rotate_single_cell(self, registry, registered_gaid):
        original_rule = registered_gaid.current_ruleset.get(
            ArtifactType.ALG, Operation.EXECUTE,
        )
        assert original_rule.min_strength == StrengthLevel.SAID_ONLY

        registry.rotate_cells(
            gaid=registered_gaid.gaid,
            changes=[CellChange(
                artifact_type=ArtifactType.ALG,
                operation=Operation.EXECUTE,
                previous_strength=StrengthLevel.SAID_ONLY,
                new_strength=StrengthLevel.KEL_ANCHORED,
                rationale="Require key-state for algorithm execution",
            )],
            new_version="1.1.0",
        )

        new_rule = registered_gaid.current_ruleset.get(
            ArtifactType.ALG, Operation.EXECUTE,
        )
        assert new_rule.min_strength == StrengthLevel.KEL_ANCHORED

    def test_rotate_records_changes(self, registry, registered_gaid):
        registry.rotate_cells(
            gaid=registered_gaid.gaid,
            changes=[CellChange(
                artifact_type=ArtifactType.ALG,
                operation=Operation.EXECUTE,
                previous_strength=StrengthLevel.SAID_ONLY,
                new_strength=StrengthLevel.KEL_ANCHORED,
                rationale="Test change",
            )],
            new_version="1.1.0",
        )
        v1 = registered_gaid.versions[1]
        assert len(v1.changes) == 1
        assert v1.changes[0].cell_key == "alg:execute"

    def test_other_cells_unchanged(self, registry, registered_gaid):
        """Non-rotated cells remain the same."""
        original_register_rule = registered_gaid.current_ruleset.get(
            ArtifactType.ALG, Operation.REGISTER,
        )
        assert original_register_rule.min_strength == StrengthLevel.TEL_ANCHORED

        registry.rotate_cells(
            gaid=registered_gaid.gaid,
            changes=[CellChange(
                artifact_type=ArtifactType.ALG,
                operation=Operation.EXECUTE,
                previous_strength=StrengthLevel.SAID_ONLY,
                new_strength=StrengthLevel.KEL_ANCHORED,
                rationale="Only changing execute",
            )],
            new_version="1.1.0",
        )

        register_rule = registered_gaid.current_ruleset.get(
            ArtifactType.ALG, Operation.REGISTER,
        )
        assert register_rule.min_strength == StrengthLevel.TEL_ANCHORED


# ---------------------------------------------------------------------------
# TestMetaGovernance
# ---------------------------------------------------------------------------


class TestMetaGovernance:
    """Test meta-governance rule enforcement."""

    def test_require_rationale_enforced(self, registry):
        gaid_obj = registry.register(
            name="strict",
            ruleset=default_cardinal_rules(),
            governance_rules=CardinalRuleSetGovernanceRules(require_rationale=True),
        )

        with pytest.raises(ValueError, match="Rationale required"):
            registry.rotate_cells(
                gaid=gaid_obj.gaid,
                changes=[CellChange(
                    artifact_type=ArtifactType.ALG,
                    operation=Operation.EXECUTE,
                    previous_strength=StrengthLevel.SAID_ONLY,
                    new_strength=StrengthLevel.KEL_ANCHORED,
                    rationale="",  # Empty!
                )],
                new_version="1.1.0",
            )

    def test_max_cells_per_rotation(self, registry):
        gaid_obj = registry.register(
            name="limited",
            ruleset=default_cardinal_rules(),
            governance_rules=CardinalRuleSetGovernanceRules(
                max_cells_per_rotation=1,
                require_rationale=False,
            ),
        )

        with pytest.raises(ValueError, match="Too many cell changes"):
            registry.rotate_cells(
                gaid=gaid_obj.gaid,
                changes=[
                    CellChange(
                        ArtifactType.ALG, Operation.EXECUTE,
                        StrengthLevel.SAID_ONLY, StrengthLevel.KEL_ANCHORED,
                        "First",
                    ),
                    CellChange(
                        ArtifactType.ALG, Operation.VERIFY,
                        StrengthLevel.SAID_ONLY, StrengthLevel.KEL_ANCHORED,
                        "Second",
                    ),
                ],
                new_version="1.1.0",
            )

    def test_monotonic_up_enforced(self, registry):
        gaid_obj = registry.register(
            name="ratchet-up",
            ruleset=default_cardinal_rules(),
            governance_rules=CardinalRuleSetGovernanceRules(
                allowed_strength_directions="monotonic_up",
                require_rationale=False,
            ),
        )

        # Weakening should fail
        with pytest.raises(ValueError, match="Monotonic-up violation"):
            registry.rotate_cells(
                gaid=gaid_obj.gaid,
                changes=[CellChange(
                    ArtifactType.ALG, Operation.REGISTER,
                    StrengthLevel.TEL_ANCHORED, StrengthLevel.SAID_ONLY,
                    "Weakening",
                )],
                new_version="1.1.0",
            )

    def test_monotonic_down_enforced(self, registry):
        gaid_obj = registry.register(
            name="relax-only",
            ruleset=default_cardinal_rules(),
            governance_rules=CardinalRuleSetGovernanceRules(
                allowed_strength_directions="monotonic_down",
                require_rationale=False,
            ),
        )

        # Strengthening should fail
        with pytest.raises(ValueError, match="Monotonic-down violation"):
            registry.rotate_cells(
                gaid=gaid_obj.gaid,
                changes=[CellChange(
                    ArtifactType.ALG, Operation.EXECUTE,
                    StrengthLevel.SAID_ONLY, StrengthLevel.TEL_ANCHORED,
                    "Strengthening",
                )],
                new_version="1.1.0",
            )

    def test_any_direction_allowed(self, registry):
        gaid_obj = registry.register(
            name="flexible",
            ruleset=default_cardinal_rules(),
            governance_rules=CardinalRuleSetGovernanceRules(
                allowed_strength_directions="any",
                require_rationale=False,
            ),
        )

        # Both directions should work
        registry.rotate_cells(
            gaid=gaid_obj.gaid,
            changes=[CellChange(
                ArtifactType.ALG, Operation.EXECUTE,
                StrengthLevel.SAID_ONLY, StrengthLevel.TEL_ANCHORED,
                "Up",
            )],
            new_version="1.1.0",
        )
        registry.rotate_cells(
            gaid=gaid_obj.gaid,
            changes=[CellChange(
                ArtifactType.ALG, Operation.EXECUTE,
                StrengthLevel.TEL_ANCHORED, StrengthLevel.SAID_ONLY,
                "Down",
            )],
            new_version="1.2.0",
        )
        assert len(gaid_obj.versions) == 3


# ---------------------------------------------------------------------------
# TestGovernedChecker
# ---------------------------------------------------------------------------


class TestGovernedChecker:
    """Test the governed checker bridge."""

    def test_check_allowed(self, registry, registered_gaid):
        checker = GovernedCardinalChecker(registry=registry, gaid_name="test-cardinal")
        result = checker.check(
            ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
        )
        assert result.allowed
        assert result.matrix_gaid == registered_gaid.gaid
        assert result.matrix_version == "1.0.0"

    def test_check_denied(self, registry, registered_gaid):
        checker = GovernedCardinalChecker(registry=registry, gaid_name="test-cardinal")
        result = checker.check(
            ArtifactType.ALG, Operation.REGISTER, StrengthLevel.SAID_ONLY,
        )
        assert not result.allowed

    def test_check_stamps_provenance(self, registry, registered_gaid):
        checker = GovernedCardinalChecker(registry=registry, gaid_name="test-cardinal")
        result = checker.check(
            ArtifactType.ALG, Operation.RESOLVE, StrengthLevel.ANY,
        )
        assert result.matrix_gaid
        assert result.matrix_said
        assert result.matrix_version

    def test_check_all_returns_governed_results(self, registry, registered_gaid):
        checker = GovernedCardinalChecker(registry=registry, gaid_name="test-cardinal")
        results = checker.check_all(ArtifactType.ALG, StrengthLevel.TEL_ANCHORED)
        assert len(results) > 0
        for op, result in results.items():
            assert isinstance(result, GovernedCheckResult)
            assert result.matrix_gaid == registered_gaid.gaid

    def test_to_dict_includes_provenance(self, registry, registered_gaid):
        checker = GovernedCardinalChecker(registry=registry, gaid_name="test-cardinal")
        result = checker.check(
            ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
        )
        d = result.to_dict()
        assert "matrix_gaid" in d
        assert "matrix_said" in d
        assert "matrix_version" in d


# ---------------------------------------------------------------------------
# TestRegistry
# ---------------------------------------------------------------------------


class TestRegistry:
    """Test registry operations."""

    def test_resolve_by_name(self, registry, registered_gaid):
        resolved = registry.resolve("test-cardinal")
        assert resolved is registered_gaid

    def test_resolve_by_gaid(self, registry, registered_gaid):
        resolved = registry.resolve(registered_gaid.gaid)
        assert resolved is registered_gaid

    def test_resolve_by_prefix(self, registry, registered_gaid):
        prefix = registered_gaid.gaid[:8]
        resolved = registry.resolve(prefix)
        assert resolved is registered_gaid

    def test_resolve_missing_returns_none(self, registry):
        assert registry.resolve("nonexistent") is None

    def test_verify_passes(self, registry, registered_gaid):
        result = registry.verify(registered_gaid.gaid)
        assert result.verified
        assert result.expected_said == result.actual_said

    def test_verify_not_found(self, registry):
        result = registry.verify("nonexistent")
        assert not result.verified
        assert "not found" in result.violations[0]

    def test_deprecate(self, registry, registered_gaid):
        registry.deprecate(
            gaid=registered_gaid.gaid,
            reason="Replaced by v2",
            successor_gaid="ENEWGAID...",
        )
        assert registered_gaid.status == CardinalRuleSetStatus.DEPRECATED
        assert registered_gaid.deprecation.reason == "Replaced by v2"
        assert registered_gaid.is_deprecated

    def test_list_excludes_deprecated(self, registry, registered_gaid):
        assert len(registry.list_rulesets()) == 1
        registry.deprecate(gaid=registered_gaid.gaid, reason="Old")
        assert len(registry.list_rulesets()) == 0
        assert len(registry.list_rulesets(include_deprecated=True)) == 1


# ---------------------------------------------------------------------------
# TestDiff
# ---------------------------------------------------------------------------


class TestDiff:
    """Test cell-level diffing."""

    def test_no_diff_for_identical(self, default_ruleset):
        changes = compute_diff(default_ruleset, default_cardinal_rules())
        assert len(changes) == 0

    def test_diff_detects_strength_change(self, default_ruleset):
        modified = default_cardinal_rules()
        modified.add(CardinalRule(
            ArtifactType.ALG, Operation.EXECUTE,
            StrengthLevel.TEL_ANCHORED,
            "Changed",
        ))
        changes = compute_diff(default_ruleset, modified)
        assert len(changes) == 1
        assert changes[0].artifact_type == ArtifactType.ALG
        assert changes[0].operation == Operation.EXECUTE
        assert changes[0].previous_strength == StrengthLevel.SAID_ONLY
        assert changes[0].new_strength == StrengthLevel.TEL_ANCHORED

    def test_cell_change_to_dict(self):
        change = CellChange(
            artifact_type=ArtifactType.ALG,
            operation=Operation.EXECUTE,
            previous_strength=StrengthLevel.SAID_ONLY,
            new_strength=StrengthLevel.KEL_ANCHORED,
            rationale="Test",
        )
        d = change.to_dict()
        assert d["cell"] == "alg:execute"
        assert d["previous"] == "SAID_ONLY"
        assert d["new"] == "KEL_ANCHORED"


# ---------------------------------------------------------------------------
# TestDefaultGenesisRules
# ---------------------------------------------------------------------------


class TestDefaultGenesisRules:
    """Test the singleton with default genesis rules."""

    def test_singleton_registers_default(self):
        registry = get_cardinal_ruleset_registry()
        gaid_obj = registry.resolve("cardinal-default")
        assert gaid_obj is not None
        assert gaid_obj.current_version.version == "1.0.0"
        assert len(gaid_obj.current_ruleset) == 33

    def test_singleton_returns_same_instance(self):
        r1 = get_cardinal_ruleset_registry()
        r2 = get_cardinal_ruleset_registry()
        assert r1 is r2

    def test_singleton_verifies(self):
        registry = get_cardinal_ruleset_registry()
        gaid_obj = registry.resolve("cardinal-default")
        result = registry.verify(gaid_obj.gaid)
        assert result.verified

    def test_governance_rules_serialization(self):
        rules = CardinalRuleSetGovernanceRules(
            min_rotation_strength=StrengthLevel.TEL_ANCHORED,
            require_rationale=True,
            max_cells_per_rotation=5,
            allowed_strength_directions="monotonic_up",
        )
        d = rules.to_dict()
        restored = CardinalRuleSetGovernanceRules.from_dict(d)
        assert restored.min_rotation_strength == StrengthLevel.TEL_ANCHORED
        assert restored.require_rationale is True
        assert restored.max_cells_per_rotation == 5
        assert restored.allowed_strength_directions == "monotonic_up"

    def test_gaid_to_dict(self):
        registry = get_cardinal_ruleset_registry()
        gaid_obj = registry.resolve("cardinal-default")
        d = gaid_obj.to_dict()
        assert d["name"] == "cardinal-default"
        assert d["status"] == "active"
        assert d["version_count"] == 1
        assert d["current_version"] == "1.0.0"
        assert d["current_matrix_said"]
