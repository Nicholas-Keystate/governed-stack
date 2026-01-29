# -*- encoding: utf-8 -*-
"""
Tests for RuntimeGAID module.

Tests:
- RuntimeManifest creation and SAID computation
- RuntimeGAIDRegistry registration and verification
- RuntimeChecker environment checking
- RuntimeResolver dependency resolution
- Integration with AlgorithmDAIDRegistry
"""

import pytest
import tempfile
from pathlib import Path

from keri_sec.runtime import (
    RuntimeManifest,
    capture_current_manifest,
    load_manifest,
    save_manifest,
    RuntimeGAID,
    RuntimeGAIDRegistry,
    RuntimeStatus,
    GovernanceRules,
    VerificationResult,
    get_runtime_gaid_registry,
    reset_runtime_gaid_registry,
    RuntimeChecker,
    CheckResult,
    ViolationSeverity,
    RuntimeResolver,
    DependencyGraph,
)

from keri_sec.algorithms import (
    AlgorithmDAIDRegistry,
    AlgorithmCategory,
    get_algorithm_daid_registry,
    reset_algorithm_daid_registry,
)


class TestRuntimeManifest:
    """Tests for RuntimeManifest dataclass."""

    def test_create_manifest(self):
        """Test creating a RuntimeManifest."""
        manifest = RuntimeManifest(
            python_version="3.12.12",
            keripy_version="1.3.3",
            keripy_said="EKERIPY_SAID_TEST",
            hio_version="0.6.19",
            algorithm_gaids={"blake3": "EBLAKE3_GAID"},
            protocol_gaids={"cesr": "ECESR_GAID"},
        )

        assert manifest.python_version == "3.12.12"
        assert manifest.keripy_version == "1.3.3"
        assert "blake3" in manifest.algorithm_gaids

    def test_manifest_said_computation(self):
        """Test that SAID is computed deterministically."""
        fixed_time = "2026-01-01T00:00:00+00:00"

        manifest1 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        manifest2 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        # Same content = same SAID
        assert manifest1.said == manifest2.said
        assert manifest1.said.startswith("E")

    def test_manifest_said_changes_with_content(self):
        """Test that SAID changes when content changes."""
        manifest1 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        manifest2 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.1",  # Different version
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        assert manifest1.said != manifest2.said

    def test_manifest_serialization(self):
        """Test manifest to_dict/from_dict."""
        manifest = RuntimeManifest(
            python_version="3.12.12",
            keripy_version="1.3.3",
            keripy_said="EKERIPY_SAID",
            hio_version="0.6.19",
            algorithm_gaids={"blake3": "EBLAKE3"},
            governance_framework_said="EFRAMEWORK",
        )

        # Force SAID computation
        _ = manifest.said

        data = manifest.to_dict()
        restored = RuntimeManifest.from_dict(data)

        assert restored.python_version == manifest.python_version
        assert restored.keripy_version == manifest.keripy_version
        assert restored.algorithm_gaids == manifest.algorithm_gaids
        assert restored.governance_framework_said == manifest.governance_framework_said

    def test_manifest_file_io(self):
        """Test manifest save/load."""
        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            save_manifest(manifest, path)
            loaded = load_manifest(path)

            assert loaded.python_version == manifest.python_version
            assert loaded.keripy_version == manifest.keripy_version
        finally:
            Path(path).unlink(missing_ok=True)

    def test_capture_current_manifest(self):
        """Test capturing current environment."""
        reset_algorithm_daid_registry()
        algo_registry = get_algorithm_daid_registry()

        manifest = capture_current_manifest(algorithm_registry=algo_registry)

        # Should have real Python version
        assert manifest.python_version.startswith("3.")

        # Should have keripy version (since it's installed)
        assert manifest.keripy_version != "not_installed"

        # Should have algorithm GAIDs from registry
        assert "blake3" in manifest.algorithm_gaids

        # Should have platform info
        assert "system" in manifest.platform_info

    def test_manifest_matches(self):
        """Test manifest comparison."""
        fixed_time = "2026-01-01T00:00:00+00:00"

        manifest1 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        manifest2 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        manifest3 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.1",  # Different
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        assert manifest1.matches(manifest2, strict=True)
        assert manifest1.matches(manifest2, strict=False)
        assert not manifest1.matches(manifest3, strict=True)
        assert not manifest1.matches(manifest3, strict=False)


class TestRuntimeGAIDRegistry:
    """Tests for RuntimeGAIDRegistry."""

    def setup_method(self):
        """Reset registries before each test."""
        reset_runtime_gaid_registry()
        reset_algorithm_daid_registry()

    def test_register_runtime(self):
        """Test registering a runtime GAID."""
        registry = RuntimeGAIDRegistry()

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        runtime = registry.register(
            name="test-runtime",
            manifest=manifest,
            version="1.0.0",
        )

        assert runtime.gaid.startswith("E")
        assert runtime.name == "test-runtime"
        assert runtime.current_version.version == "1.0.0"
        assert runtime.current_manifest.keripy_version == "1.3.0"

    def test_resolve_by_gaid(self):
        """Test resolving runtime by GAID."""
        registry = RuntimeGAIDRegistry()

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        runtime = registry.register(name="resolvable", manifest=manifest)

        # Resolve by full GAID
        resolved = registry.resolve(runtime.gaid)
        assert resolved is not None
        assert resolved.name == "resolvable"

        # Resolve by prefix
        resolved = registry.resolve(runtime.gaid[:16])
        assert resolved is not None

        # Resolve by name
        resolved = registry.resolve("resolvable")
        assert resolved is not None

    def test_runtime_rotation(self):
        """Test rotating a runtime to new manifest."""
        registry = RuntimeGAIDRegistry()

        manifest1 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY_V1",
            hio_version="0.6.0",
        )

        runtime = registry.register(
            name="rotating",
            manifest=manifest1,
            version="1.0.0",
        )

        original_gaid = runtime.gaid

        # Rotate to new manifest
        manifest2 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.1",
            keripy_said="EKERIPY_V2",
            hio_version="0.6.0",
        )

        registry.rotate(
            gaid=runtime.gaid,
            new_manifest=manifest2,
            new_version="1.1.0",
        )

        # GAID stays the same
        assert runtime.gaid == original_gaid

        # Version chain has 2 entries
        assert len(runtime.versions) == 2

        # Current is the new version
        assert runtime.current_version.version == "1.1.0"
        assert runtime.current_manifest.keripy_version == "1.3.1"

    def test_verify_runtime(self):
        """Test verifying current environment against runtime GAID."""
        reset_algorithm_daid_registry()
        algo_registry = get_algorithm_daid_registry()

        registry = RuntimeGAIDRegistry(algorithm_registry=algo_registry)

        # Capture current environment
        current = capture_current_manifest(algorithm_registry=algo_registry)

        # Register with governance rules
        runtime = registry.register(
            name="verified",
            manifest=current,
            governance_rules=GovernanceRules(
                min_python_version="3.10.0",
                min_keripy_version="1.0.0",
            ),
        )

        # Verify against current (should pass)
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert result.compliant
        assert len(result.violations) == 0

    def test_verify_with_violations(self):
        """Test verification with violations."""
        registry = RuntimeGAIDRegistry()

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        # Register with strict rules
        runtime = registry.register(
            name="strict",
            manifest=manifest,
            governance_rules=GovernanceRules(
                min_python_version="3.99.0",  # Impossible to satisfy
            ),
        )

        # Verify (should fail)
        result = registry.verify(runtime.gaid)
        assert not result.compliant
        assert len(result.violations) > 0
        assert "Python" in result.violations[0]

    def test_deprecate_runtime(self):
        """Test deprecating a runtime GAID."""
        registry = RuntimeGAIDRegistry()

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        runtime = registry.register(name="to-deprecate", manifest=manifest)

        # Deprecate
        registry.deprecate(
            gaid=runtime.gaid,
            reason="Outdated keripy",
            successor_gaid="ENEW_RUNTIME_GAID",
        )

        assert runtime.is_deprecated
        assert runtime.status == RuntimeStatus.DEPRECATED
        assert runtime.deprecation.reason == "Outdated keripy"


class TestRuntimeChecker:
    """Tests for RuntimeChecker."""

    def test_check_matching_manifest(self):
        """Test checking matching manifests."""
        checker = RuntimeChecker()

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        # Check against itself (trivially passes)
        result = checker.check(manifest, manifest)
        assert result.passed
        assert result.error_count == 0

    def test_check_version_mismatch(self):
        """Test detecting version mismatches."""
        checker = RuntimeChecker()

        expected = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        actual = RuntimeManifest(
            python_version="3.11.0",  # Major.minor differs
            keripy_version="1.2.0",   # Version differs
            keripy_said="EKERIPY_DIFF",  # SAID differs
            hio_version="0.6.0",
        )

        result = checker.check(expected, actual)
        assert not result.passed
        assert result.error_count >= 2  # Python and keripy

    def test_check_algorithm_mismatch(self):
        """Test detecting algorithm mismatches."""
        checker = RuntimeChecker(strict_algorithms=True)

        expected = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            algorithm_gaids={"blake3": "EBLAKE3_EXPECTED"},
        )

        actual = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            algorithm_gaids={"blake3": "EBLAKE3_DIFFERENT"},
        )

        result = checker.check(expected, actual)
        assert not result.passed
        assert any("blake3" in v.component for v in result.violations)

    def test_check_said_only(self):
        """Test quick SAID-only check."""
        checker = RuntimeChecker()

        # Create a fixed manifest (not captured - timestamps would differ)
        fixed_time = "2026-01-01T00:00:00+00:00"
        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
            created_at=fixed_time,
        )

        # Check against known SAID
        result = checker.check(manifest, manifest)  # Compare to self
        assert result.passed

        # SAID doesn't match
        result = checker.check_said_only("EWRONG_SAID")
        assert not result.passed


class TestRuntimeResolver:
    """Tests for RuntimeResolver."""

    def setup_method(self):
        """Reset registries before each test."""
        reset_runtime_gaid_registry()
        reset_algorithm_daid_registry()

    def test_resolve_dependencies(self):
        """Test resolving runtime dependencies."""
        algo_registry = get_algorithm_daid_registry()
        runtime_registry = RuntimeGAIDRegistry(algorithm_registry=algo_registry)

        # Capture current with algorithm GAIDs
        manifest = capture_current_manifest(algorithm_registry=algo_registry)
        runtime = runtime_registry.register(name="resolved", manifest=manifest)

        resolver = RuntimeResolver(
            runtime_registry=runtime_registry,
            algorithm_registry=algo_registry,
        )

        graph = resolver.resolve_dependencies(runtime.gaid)

        assert graph.runtime_name == "resolved"
        assert len(graph.dependencies) > 0

        # Should have resolved algorithms
        algo_deps = [d for d in graph.dependencies if d.category == "algorithm"]
        assert len(algo_deps) > 0

    def test_check_availability(self):
        """Test checking dependency availability."""
        algo_registry = get_algorithm_daid_registry()
        runtime_registry = RuntimeGAIDRegistry(algorithm_registry=algo_registry)

        manifest = capture_current_manifest(algorithm_registry=algo_registry)
        runtime = runtime_registry.register(name="available", manifest=manifest)

        resolver = RuntimeResolver(
            runtime_registry=runtime_registry,
            algorithm_registry=algo_registry,
        )

        result = resolver.check_availability(runtime.gaid)

        # Should be available since we captured current
        assert result.available
        assert len(result.missing) == 0

    def test_supersession_chain(self):
        """Test walking supersession chain."""
        algo_registry = get_algorithm_daid_registry()
        runtime_registry = RuntimeGAIDRegistry(algorithm_registry=algo_registry)

        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="EKERIPY",
            hio_version="0.6.0",
        )

        runtime1 = runtime_registry.register(name="v1", manifest=manifest)
        runtime2 = runtime_registry.register(name="v2", manifest=manifest)

        # Deprecate v1 in favor of v2
        runtime_registry.deprecate(
            gaid=runtime1.gaid,
            reason="Upgraded",
            successor_gaid=runtime2.gaid,
        )

        resolver = RuntimeResolver(
            runtime_registry=runtime_registry,
            algorithm_registry=algo_registry,
        )

        chain = resolver.get_supersession_chain(runtime1.gaid)
        assert len(chain) == 2
        assert chain[0] == runtime1.gaid
        assert chain[1] == runtime2.gaid

        # Get latest should return v2
        latest = resolver.get_latest_in_chain(runtime1.gaid)
        assert latest == runtime2.gaid


class TestIntegrationWithAlgorithmRegistry:
    """Integration tests with AlgorithmDAIDRegistry."""

    def setup_method(self):
        reset_runtime_gaid_registry()
        reset_algorithm_daid_registry()

    def test_end_to_end_verification(self):
        """Test full workflow: capture, register, verify."""
        # Get algorithm registry with core algorithms
        algo_registry = get_algorithm_daid_registry()

        # Capture current environment
        manifest = capture_current_manifest(algorithm_registry=algo_registry)

        # Register as governed runtime
        runtime_registry = RuntimeGAIDRegistry(algorithm_registry=algo_registry)
        runtime = runtime_registry.register(
            name="production",
            manifest=manifest,
            governance_rules=GovernanceRules(
                min_python_version="3.10.0",
                min_keripy_version="1.0.0",
                required_algorithms=["blake3"],
            ),
        )

        # Verify (should pass since we captured current)
        result = runtime_registry.verify(runtime.gaid)
        assert result.compliant, f"Violations: {result.violations}"

        # Check dependencies
        resolver = RuntimeResolver(
            runtime_registry=runtime_registry,
            algorithm_registry=algo_registry,
        )
        availability = resolver.check_availability(runtime.gaid)
        assert availability.available

    def test_algorithm_gaid_in_manifest(self):
        """Test that algorithm GAIDs are included in manifest."""
        algo_registry = get_algorithm_daid_registry()

        # Get blake3 GAID
        blake3 = algo_registry.resolve("blake3")
        assert blake3 is not None

        manifest = capture_current_manifest(algorithm_registry=algo_registry)

        # Manifest should contain blake3 GAID
        assert "blake3" in manifest.algorithm_gaids
        assert manifest.algorithm_gaids["blake3"] == blake3.daid


class TestGovernanceRulesEnforcement:
    """Test governance rules edge cases (binding taxonomy Layer 10)."""

    def _make_registry_with_rules(self, rules):
        """Helper: create registry with a runtime governed by given rules."""
        registry = RuntimeGAIDRegistry()
        manifest = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
            algorithm_gaids={"blake3": "E_BLAKE3", "ed25519": "E_ED25519"},
            platform_info={"system": "Darwin"},
        )
        runtime = registry.register(
            name="test-governed",
            manifest=manifest,
            governance_rules=rules,
        )
        return registry, runtime

    def test_forbidden_algorithms_violation(self):
        """Forbidden algorithms should produce violations."""
        rules = GovernanceRules(forbidden_algorithms=["sha256"])
        registry, runtime = self._make_registry_with_rules(rules)

        # Manifest with forbidden algorithm
        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
            algorithm_gaids={"blake3": "E_BLAKE3", "sha256": "E_SHA256"},
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert not result.compliant
        assert any("sha256" in v for v in result.violations)

    def test_forbidden_algorithms_pass(self):
        """No forbidden algorithms present should pass."""
        rules = GovernanceRules(forbidden_algorithms=["sha256"])
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
            algorithm_gaids={"blake3": "E_BLAKE3"},
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert result.compliant

    def test_max_python_version_violation(self):
        """Python version above max should fail."""
        rules = GovernanceRules(max_python_version="3.12.99")
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.13.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert not result.compliant
        assert any("Python" in v and ">" in v for v in result.violations)

    def test_max_keripy_version_violation(self):
        """keripy version above max should fail."""
        rules = GovernanceRules(max_keripy_version="1.2.99")
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert not result.compliant
        assert any("keripy" in v for v in result.violations)

    def test_platform_restriction(self):
        """Platform not in allowed list should fail."""
        rules = GovernanceRules(allowed_platforms=["Linux"])
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
            platform_info={"system": "Darwin"},
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert not result.compliant
        assert any("Platform" in v for v in result.violations)

    def test_multiple_violations(self):
        """Multiple rule violations should all be reported."""
        rules = GovernanceRules(
            min_python_version="3.13.0",
            min_keripy_version="2.0.0",
            required_algorithms=["missing_algo"],
            forbidden_algorithms=["blake3"],
        )
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
            algorithm_gaids={"blake3": "E_BLAKE3"},
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert not result.compliant
        assert len(result.violations) >= 4  # python, keripy, required, forbidden

    def test_empty_rules_always_compliant(self):
        """Empty governance rules should always pass."""
        rules = GovernanceRules()
        registry, runtime = self._make_registry_with_rules(rules)

        current = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",
            keripy_said="E_TEST",
            hio_version="0.6.14",
        )
        result = registry.verify(runtime.gaid, current_manifest=current)
        assert result.compliant

    def test_governance_rules_serialization(self):
        """GovernanceRules should round-trip through to_dict/from_dict."""
        rules = GovernanceRules(
            min_python_version="3.12.0",
            max_python_version="3.13.99",
            min_keripy_version="1.2.0",
            max_keripy_version="1.99.0",
            required_algorithms=["blake3", "ed25519"],
            forbidden_algorithms=["sha256"],
            allowed_platforms=["Darwin", "Linux"],
        )
        d = rules.to_dict()
        restored = GovernanceRules.from_dict(d)
        assert restored.min_python_version == "3.12.0"
        assert restored.max_python_version == "3.13.99"
        assert restored.required_algorithms == ["blake3", "ed25519"]
        assert restored.forbidden_algorithms == ["sha256"]
        assert restored.allowed_platforms == ["Darwin", "Linux"]


class TestVersionChainIntegrity:
    """Test RuntimeGAID version chain integrity."""

    def test_version_chain_append_only(self):
        """Version chain should be append-only."""
        registry = RuntimeGAIDRegistry()
        m1 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.2.0",
            keripy_said="E_V1", hio_version="0.6.14",
        )
        runtime = registry.register("chain-test", m1,
            governance_rules=GovernanceRules(min_keripy_version="1.0.0"),
            version="1.0.0")

        assert len(runtime.versions) == 1

        m2 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.3.0",
            keripy_said="E_V2", hio_version="0.6.14",
        )
        registry.rotate(runtime.gaid, m2, "2.0.0")

        assert len(runtime.versions) == 2
        assert runtime.versions[0].version == "1.0.0"
        assert runtime.versions[1].version == "2.0.0"
        assert runtime.current_version.version == "2.0.0"

    def test_gaid_stable_through_rotations(self):
        """GAID should remain stable through manifest rotations."""
        registry = RuntimeGAIDRegistry()
        m1 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.2.0",
            keripy_said="E_V1", hio_version="0.6.14",
        )
        runtime = registry.register("stable-test", m1, version="1.0.0")
        original_gaid = runtime.gaid

        m2 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.3.0",
            keripy_said="E_V2", hio_version="0.6.14",
        )
        registry.rotate(runtime.gaid, m2, "2.0.0")
        assert runtime.gaid == original_gaid

        m3 = RuntimeManifest(
            python_version="3.13.0", keripy_version="1.4.0",
            keripy_said="E_V3", hio_version="0.7.0",
        )
        registry.rotate(runtime.gaid, m3, "3.0.0")
        assert runtime.gaid == original_gaid

    def test_rotation_inherits_rules(self):
        """Rotation without new rules should inherit current rules."""
        registry = RuntimeGAIDRegistry()
        rules = GovernanceRules(min_keripy_version="1.2.0", required_algorithms=["blake3"])
        m1 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.2.0",
            keripy_said="E_V1", hio_version="0.6.14",
        )
        runtime = registry.register("inherit-test", m1,
            governance_rules=rules, version="1.0.0")

        m2 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.3.0",
            keripy_said="E_V2", hio_version="0.6.14",
        )
        new_ver = registry.rotate(runtime.gaid, m2, "2.0.0")
        assert new_ver.governance_rules.min_keripy_version == "1.2.0"
        assert new_ver.governance_rules.required_algorithms == ["blake3"]

    def test_rotation_with_new_rules(self):
        """Rotation with new rules should use new rules."""
        registry = RuntimeGAIDRegistry()
        m1 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.2.0",
            keripy_said="E_V1", hio_version="0.6.14",
        )
        runtime = registry.register("newrules-test", m1,
            governance_rules=GovernanceRules(min_keripy_version="1.0.0"),
            version="1.0.0")

        m2 = RuntimeManifest(
            python_version="3.12.0", keripy_version="1.3.0",
            keripy_said="E_V2", hio_version="0.6.14",
        )
        new_rules = GovernanceRules(min_keripy_version="1.3.0", required_algorithms=["ed25519"])
        new_ver = registry.rotate(runtime.gaid, m2, "2.0.0", new_rules=new_rules)
        assert new_ver.governance_rules.min_keripy_version == "1.3.0"
        assert new_ver.governance_rules.required_algorithms == ["ed25519"]
