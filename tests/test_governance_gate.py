# -*- encoding: utf-8 -*-
"""
Tests for GovernanceGate - cardinal rule enforcement on GAID operations.

Tests:
- Tier <-> StrengthLevel mapping
- infer_strength logic
- GovernanceGate enforcement (allow/deny)
- Registry integration (all 4 registries)
- Two-phase lifecycle (ungoverned genesis, then gated)
"""

import pytest
from unittest.mock import MagicMock, patch

from keri_governance.cardinal import ArtifactType, CardinalCheckResult, CardinalRule, Operation
from keri_governance.primitives import StrengthLevel

from keri_sec.attestation import Tier
from keri_sec.governance.gate import (
    TIER_TO_STRENGTH,
    STRENGTH_TO_TIER,
    GovernanceGate,
    GovernanceViolation,
    infer_strength,
    strength_to_tier,
    tier_to_strength,
)
from keri_sec.governance.cardinal_checker_bridge import GovernedCheckResult


# ---------------------------------------------------------------------------
# TestTierMapping
# ---------------------------------------------------------------------------


class TestTierMapping:
    """Test Tier <-> StrengthLevel mapping with inverted ordinals."""

    def test_tel_anchored_maps_correctly(self):
        assert tier_to_strength(Tier.TEL_ANCHORED) == StrengthLevel.TEL_ANCHORED

    def test_kel_anchored_maps_correctly(self):
        assert tier_to_strength(Tier.KEL_ANCHORED) == StrengthLevel.KEL_ANCHORED

    def test_said_only_maps_correctly(self):
        assert tier_to_strength(Tier.SAID_ONLY) == StrengthLevel.SAID_ONLY

    def test_roundtrip_all_tiers(self):
        for tier in Tier:
            strength = tier_to_strength(tier)
            assert strength_to_tier(strength) == tier

    def test_strength_any_has_no_tier(self):
        assert strength_to_tier(StrengthLevel.ANY) is None

    def test_mapping_dict_completeness(self):
        """Every Tier value must appear in the mapping."""
        for tier in Tier:
            assert tier in TIER_TO_STRENGTH

    def test_inverted_ordinals(self):
        """Verify that the ordinals are truly inverted."""
        # Tier: TEL=1 (strongest), SAID=3 (weakest)
        assert Tier.TEL_ANCHORED.value < Tier.SAID_ONLY.value
        # StrengthLevel: TEL=3 (strongest), SAID=1 (weakest)
        assert StrengthLevel.TEL_ANCHORED.value > StrengthLevel.SAID_ONLY.value


# ---------------------------------------------------------------------------
# TestInferStrength
# ---------------------------------------------------------------------------


class TestInferStrength:
    """Test StrengthLevel inference from attestation context."""

    def test_no_hab_no_tier_returns_said_only(self):
        assert infer_strength() == StrengthLevel.SAID_ONLY

    def test_hab_present_returns_kel_anchored(self):
        mock_hab = MagicMock()
        assert infer_strength(issuer_hab=mock_hab) == StrengthLevel.KEL_ANCHORED

    def test_explicit_tier_overrides_hab(self):
        mock_hab = MagicMock()
        result = infer_strength(
            issuer_hab=mock_hab,
            explicit_tier=Tier.TEL_ANCHORED,
        )
        assert result == StrengthLevel.TEL_ANCHORED

    def test_explicit_tier_without_hab(self):
        result = infer_strength(explicit_tier=Tier.KEL_ANCHORED)
        assert result == StrengthLevel.KEL_ANCHORED

    def test_explicit_said_only_tier(self):
        result = infer_strength(explicit_tier=Tier.SAID_ONLY)
        assert result == StrengthLevel.SAID_ONLY


# ---------------------------------------------------------------------------
# TestGovernanceGate
# ---------------------------------------------------------------------------


class TestGovernanceGate:
    """Test GovernanceGate enforcement."""

    def _make_result(self, allowed: bool, message: str = "") -> GovernedCheckResult:
        """Helper to create a GovernedCheckResult."""
        rule = CardinalRule(
            artifact_type=ArtifactType.ALG,
            operation=Operation.REGISTER,
            min_strength=StrengthLevel.TEL_ANCHORED,
        )
        actual = StrengthLevel.SAID_ONLY if not allowed else StrengthLevel.TEL_ANCHORED
        check = CardinalCheckResult(
            allowed=allowed,
            rule=rule,
            actual_strength=actual,
            message=message,
        )
        return GovernedCheckResult(
            check_result=check,
            matrix_gaid="GAID_test",
            matrix_said="SAID_test",
            matrix_version="1.0.0",
        )

    def test_enforce_allowed_returns_result(self):
        """When check passes, enforce returns the result."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(True, "ok")

        gate = GovernanceGate(artifact_type=ArtifactType.ALG, checker=mock_checker)
        result = gate.enforce(Operation.REGISTER, issuer_hab=MagicMock())

        assert result.allowed
        mock_checker.check.assert_called_once()

    def test_enforce_denied_raises_violation(self):
        """When check fails, enforce raises GovernanceViolation."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(
            False, "ALG:REGISTER requires TEL_ANCHORED, got SAID_ONLY"
        )

        gate = GovernanceGate(artifact_type=ArtifactType.ALG, checker=mock_checker)

        with pytest.raises(GovernanceViolation) as exc_info:
            gate.enforce(Operation.REGISTER)

        assert "TEL_ANCHORED" in str(exc_info.value)
        assert exc_info.value.result.matrix_gaid == "GAID_test"

    def test_enforce_passes_correct_artifact_type(self):
        """Gate passes its artifact_type to the checker."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(True)

        gate = GovernanceGate(artifact_type=ArtifactType.SCH, checker=mock_checker)
        gate.enforce(Operation.REGISTER, issuer_hab=MagicMock())

        call_args = mock_checker.check.call_args
        assert call_args[0][0] == ArtifactType.SCH

    def test_enforce_infers_strength_from_hab(self):
        """Gate infers KEL_ANCHORED when issuer_hab is provided."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(True)

        gate = GovernanceGate(artifact_type=ArtifactType.ALG, checker=mock_checker)
        gate.enforce(Operation.REGISTER, issuer_hab=MagicMock())

        call_args = mock_checker.check.call_args
        assert call_args[0][2] == StrengthLevel.KEL_ANCHORED

    def test_enforce_infers_said_only_without_hab(self):
        """Gate infers SAID_ONLY when no issuer_hab."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(True)

        gate = GovernanceGate(artifact_type=ArtifactType.ALG, checker=mock_checker)
        gate.enforce(Operation.REGISTER)

        call_args = mock_checker.check.call_args
        assert call_args[0][2] == StrengthLevel.SAID_ONLY

    def test_enforce_uses_explicit_tier(self):
        """Gate uses explicit_tier override."""
        mock_checker = MagicMock()
        mock_checker.check.return_value = self._make_result(True)

        gate = GovernanceGate(artifact_type=ArtifactType.ALG, checker=mock_checker)
        gate.enforce(Operation.REGISTER, explicit_tier=Tier.TEL_ANCHORED)

        call_args = mock_checker.check.call_args
        assert call_args[0][2] == StrengthLevel.TEL_ANCHORED

    def test_artifact_type_property(self):
        gate = GovernanceGate(artifact_type=ArtifactType.PKG)
        assert gate.artifact_type == ArtifactType.PKG


# ---------------------------------------------------------------------------
# TestGovernanceViolation
# ---------------------------------------------------------------------------


class TestGovernanceViolation:
    """Test GovernanceViolation exception."""

    def test_carries_result(self):
        rule = CardinalRule(
            artifact_type=ArtifactType.ALG,
            operation=Operation.REGISTER,
            min_strength=StrengthLevel.TEL_ANCHORED,
        )
        check = CardinalCheckResult(
            allowed=False,
            rule=rule,
            actual_strength=StrengthLevel.SAID_ONLY,
            message="insufficient strength",
        )
        result = GovernedCheckResult(
            check_result=check,
            matrix_gaid="GAID_test",
            matrix_said="SAID_test",
            matrix_version="1.0.0",
        )
        exc = GovernanceViolation(result)
        assert exc.result is result
        assert str(exc) == "insufficient strength"


# ---------------------------------------------------------------------------
# TestRegistryIntegration
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    """Test that each registry correctly calls the governance gate."""

    def _make_gate(self, artifact_type: ArtifactType, allowed: bool = True):
        """Create a mock gate that allows or denies all operations."""
        gate = MagicMock(spec=GovernanceGate)
        gate.artifact_type = artifact_type

        rule = CardinalRule(
            artifact_type=artifact_type,
            operation=Operation.REGISTER,
            min_strength=StrengthLevel.TEL_ANCHORED,
        )

        if allowed:
            check = CardinalCheckResult(
                allowed=True,
                rule=rule,
                actual_strength=StrengthLevel.SAID_ONLY,
                message="ok",
            )
            gate.enforce.return_value = GovernedCheckResult(
                check_result=check,
                matrix_gaid="GAID_test",
                matrix_said="SAID_test",
                matrix_version="1.0.0",
            )
        else:
            gate.enforce.side_effect = GovernanceViolation(
                GovernedCheckResult(
                    check_result=CardinalCheckResult(
                        allowed=False,
                        rule=rule,
                        actual_strength=StrengthLevel.SAID_ONLY,
                        message="denied",
                    ),
                    matrix_gaid="GAID_test",
                    matrix_said="SAID_test",
                    matrix_version="1.0.0",
                )
            )

        return gate

    def test_algorithm_registry_enforces_register(self):
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        gate = self._make_gate(ArtifactType.ALG, allowed=False)
        registry = AlgorithmDAIDRegistry(governance_gate=gate)

        with pytest.raises(GovernanceViolation):
            registry.register(
                name="test-alg",
                category=AlgorithmCategory.HASH,
                version="1.0.0",
                spec_said="ETEST",
            )

        gate.enforce.assert_called_once()
        call_args = gate.enforce.call_args
        assert call_args[1].get("issuer_hab") is None
        assert call_args[0][0] == Operation.REGISTER

    def test_algorithm_registry_no_gate_passes(self):
        """Without a gate, register works normally."""
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        registry = AlgorithmDAIDRegistry()  # no gate
        alg = registry.register(
            name="test-alg",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ETEST",
        )
        assert alg is not None

    def test_algorithm_registry_set_governance_gate(self):
        """set_governance_gate enables enforcement after construction."""
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        registry = AlgorithmDAIDRegistry()
        # Register without gate — should succeed
        alg = registry.register(
            name="genesis-alg",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EGENESIS",
        )
        assert alg is not None

        # Now set gate that denies
        gate = self._make_gate(ArtifactType.ALG, allowed=False)
        registry.set_governance_gate(gate)

        # This should fail
        with pytest.raises(GovernanceViolation):
            registry.register(
                name="post-gate-alg",
                category=AlgorithmCategory.HASH,
                version="1.0.0",
                spec_said="EPOST",
            )

    def test_schema_registry_enforces_register(self):
        from keri_sec.schemas.registry import SchemaDAIDRegistry

        gate = self._make_gate(ArtifactType.SCH, allowed=False)
        registry = SchemaDAIDRegistry(governance_gate=gate)

        with pytest.raises(GovernanceViolation):
            registry.register(
                name="test-schema",
                namespace="test",
                version="1.0.0",
                content={"type": "object"},
            )

        gate.enforce.assert_called_once()

    def test_package_registry_enforces_register(self):
        from keri_sec.packages.daid import PackageDAIDRegistry

        gate = self._make_gate(ArtifactType.PKG, allowed=False)
        registry = PackageDAIDRegistry(
            base_path=None,
            governance_gate=gate,
        )

        with pytest.raises(GovernanceViolation):
            registry.register(
                name="test-pkg",
                publisher_aid="EPUBLISHER",
            )

        gate.enforce.assert_called_once()

    def test_runtime_registry_enforces_register(self):
        from keri_sec.runtime.gaid import RuntimeGAIDRegistry
        from keri_sec.runtime.manifest import RuntimeManifest

        gate = self._make_gate(ArtifactType.RUN, allowed=False)
        registry = RuntimeGAIDRegistry(governance_gate=gate)

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.3",
            keripy_said="ETEST_KERIPY_SAID",
            hio_version="0.6.14",
        )

        with pytest.raises(GovernanceViolation):
            registry.register(
                name="test-runtime",
                manifest=manifest,
            )

        gate.enforce.assert_called_once()

    def test_algorithm_registry_enforces_rotate(self):
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        # First register without gate
        registry = AlgorithmDAIDRegistry()
        alg = registry.register(
            name="rot-test",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ETEST",
        )

        # Set denying gate
        gate = self._make_gate(ArtifactType.ALG, allowed=False)
        registry.set_governance_gate(gate)

        with pytest.raises(GovernanceViolation):
            registry.rotate(
                daid=alg.daid,
                new_version="2.0.0",
                new_spec_said="ENEW",
            )

    def test_algorithm_registry_enforces_deprecate(self):
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        registry = AlgorithmDAIDRegistry()
        alg = registry.register(
            name="dep-test",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ETEST",
        )

        gate = self._make_gate(ArtifactType.ALG, allowed=False)
        registry.set_governance_gate(gate)

        with pytest.raises(GovernanceViolation):
            registry.deprecate(daid=alg.daid, reason="test")


# ---------------------------------------------------------------------------
# TestTwoPhaseLifecycle
# ---------------------------------------------------------------------------


class TestTwoPhaseLifecycle:
    """Test the two-phase lifecycle: ungoverned genesis, then gated."""

    def test_genesis_ungoverned_then_gate_enforced(self):
        """Singleton pattern: genesis registrations happen without gate."""
        from keri_sec.algorithms.daid import AlgorithmDAIDRegistry, AlgorithmCategory

        # Phase 1: Create registry, register genesis (no gate)
        registry = AlgorithmDAIDRegistry()
        genesis = registry.register(
            name="blake3",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EGENESIS",
        )
        assert genesis is not None

        # Phase 2: Enable gate
        gate = MagicMock(spec=GovernanceGate)
        rule = CardinalRule(
            artifact_type=ArtifactType.ALG,
            operation=Operation.REGISTER,
            min_strength=StrengthLevel.TEL_ANCHORED,
        )
        gate.enforce.side_effect = GovernanceViolation(
            GovernedCheckResult(
                check_result=CardinalCheckResult(
                    allowed=False,
                    rule=rule,
                    actual_strength=StrengthLevel.SAID_ONLY,
                    message="denied after genesis",
                ),
                matrix_gaid="GAID_test",
                matrix_said="SAID_test",
                matrix_version="1.0.0",
            )
        )
        registry.set_governance_gate(gate)

        # Phase 2 registration should fail
        with pytest.raises(GovernanceViolation):
            registry.register(
                name="new-alg",
                category=AlgorithmCategory.HASH,
                version="1.0.0",
                spec_said="ENEW",
            )

        # But genesis algorithm is still accessible
        assert registry.resolve("blake3") is not None
