# -*- encoding: utf-8 -*-
"""Tests for DAID verification module."""

import pytest

from keri_sec.schemas import (
    SchemaDAIDRegistry,
    get_schema_registry,
    reset_schema_registry,
)
from keri_sec.algorithms import (
    AlgorithmDAIDRegistry,
    AlgorithmCategory,
    get_algorithm_daid_registry,
    reset_algorithm_daid_registry,
)
from keri_sec.daid_verification import (
    DAIDVerifier,
    SchemaVerificationResult,
    AlgorithmVerificationResult,
    CredentialVerificationResult,
    verify_schema,
    check_algorithm,
    get_schema_said_for_issuance,
)


class TestSchemaVerification:
    """Test schema DAID verification."""

    def setup_method(self):
        """Reset registries before each test."""
        reset_schema_registry()
        reset_algorithm_daid_registry()

    def test_verify_registered_schema(self):
        """Verifying a registered schema succeeds."""
        registry = get_schema_registry()

        # Register a test schema
        schema = registry.register(
            name="test-schema",
            namespace="test-ns",
            version="1.0.0",
            content={"title": "Test Schema", "type": "object"},
        )

        verifier = DAIDVerifier(schema_registry=registry)
        result = verifier.verify_schema_said(schema.current_content_said)

        assert result.verified is True
        assert result.daid == schema.daid
        assert result.name == "test-schema"
        assert result.namespace == "test-ns"

    def test_verify_unknown_schema_fails(self):
        """Verifying unknown schema SAID fails."""
        verifier = DAIDVerifier()
        result = verifier.verify_schema_said("EUNKNOWN_SAID_THAT_DOES_NOT_EXIST")

        assert result.verified is False
        assert "not found" in result.error.lower()

    def test_verify_with_expected_name(self):
        """Verification checks expected name."""
        registry = get_schema_registry()

        schema = registry.register(
            name="my-schema",
            namespace="test",
            version="1.0.0",
            content={"title": "My Schema"},
        )

        verifier = DAIDVerifier(schema_registry=registry)

        # Correct name succeeds
        result = verifier.verify_schema_said(
            schema.current_content_said,
            expected_name="my-schema",
        )
        assert result.verified is True

        # Wrong name fails
        result = verifier.verify_schema_said(
            schema.current_content_said,
            expected_name="other-schema",
        )
        assert result.verified is False
        assert "mismatch" in result.error.lower()

    def test_verify_with_expected_namespace(self):
        """Verification checks expected namespace."""
        registry = get_schema_registry()

        schema = registry.register(
            name="schema",
            namespace="my-namespace",
            version="1.0.0",
            content={"title": "Schema"},
        )

        verifier = DAIDVerifier(schema_registry=registry)

        # Wrong namespace fails
        result = verifier.verify_schema_said(
            schema.current_content_said,
            expected_namespace="wrong-namespace",
        )
        assert result.verified is False
        assert "namespace" in result.error.lower()

    def test_verify_version_pinning(self):
        """Verification validates version pinning."""
        registry = get_schema_registry()

        schema = registry.register(
            name="versioned",
            namespace="test",
            version="1.0.0",
            content={"title": "Version 1"},
        )

        # Rotate to v2
        registry.rotate(
            daid=schema.daid,
            new_version="2.0.0",
            new_content={"title": "Version 2"},
        )

        verifier = DAIDVerifier(schema_registry=registry)

        # Get v1 SAID
        v1_said = schema.pin_version("1.0.0")

        # Verify with correct version
        result = verifier.verify_schema_said(v1_said, expected_version="1.0.0")
        assert result.verified is True
        assert result.version == "1.0.0"

        # Verify with wrong version fails
        result = verifier.verify_schema_said(v1_said, expected_version="2.0.0")
        assert result.verified is False
        assert "SAID" in result.error  # Version 2.0.0 has different SAID

    def test_deprecated_schema_warns(self):
        """Deprecated schema returns warning."""
        registry = get_schema_registry()

        schema = registry.register(
            name="old-schema",
            namespace="test",
            version="1.0.0",
            content={"title": "Old"},
        )

        # Create successor
        successor = registry.register(
            name="new-schema",
            namespace="test",
            version="1.0.0",
            content={"title": "New"},
        )

        # Deprecate old
        registry.deprecate(
            daid=schema.daid,
            reason="Use new-schema instead",
            successor_daid=successor.daid,
        )

        verifier = DAIDVerifier(schema_registry=registry, warn_on_deprecated=False)
        result = verifier.verify_schema_said(schema.current_content_said)

        assert result.verified is True  # Still verifies
        assert result.deprecation_warning is not None
        assert "deprecated" in result.deprecation_warning.lower()
        assert result.successor_daid == successor.daid


class TestAlgorithmVerification:
    """Test algorithm DAID verification."""

    def setup_method(self):
        reset_algorithm_daid_registry()

    def test_check_registered_algorithm(self):
        """Checking registered algorithm succeeds."""
        registry = get_algorithm_daid_registry()

        # blake3 is registered by default
        verifier = DAIDVerifier(algorithm_registry=registry)
        result = verifier.check_algorithm_status("blake3")

        assert result.verified is True
        assert result.algorithm_name == "blake3"
        assert result.category == "hash"
        assert result.security_level == 256

    def test_check_by_cesr_code(self):
        """Can check algorithm by CESR code."""
        registry = get_algorithm_daid_registry()

        verifier = DAIDVerifier(algorithm_registry=registry)
        result = verifier.check_algorithm_status("E")  # CESR code for Blake3

        assert result.verified is True
        assert result.algorithm_name == "blake3"

    def test_check_unknown_algorithm_fails(self):
        """Checking unknown algorithm fails."""
        verifier = DAIDVerifier()
        result = verifier.check_algorithm_status("unknown-algo")

        assert result.verified is False
        assert "not found" in result.error.lower()

    def test_check_required_category(self):
        """Checking with required category validates it."""
        registry = get_algorithm_daid_registry()
        verifier = DAIDVerifier(algorithm_registry=registry)

        # Correct category succeeds
        result = verifier.check_algorithm_status("blake3", AlgorithmCategory.HASH)
        assert result.verified is True

        # Wrong category fails
        result = verifier.check_algorithm_status("blake3", AlgorithmCategory.SIGNATURE)
        assert result.verified is False
        assert "category" in result.error.lower()

    def test_check_security_level(self):
        """Checking validates minimum security level."""
        registry = get_algorithm_daid_registry()

        # sha256 has security_level=128 (quantum security)
        verifier = DAIDVerifier(algorithm_registry=registry, min_security_level=256)
        result = verifier.check_algorithm_status("sha256")

        assert result.verified is False
        assert "security level" in result.error.lower()

    def test_deprecated_algorithm_warns(self):
        """Deprecated algorithm returns warning."""
        registry = get_algorithm_daid_registry()

        # Deprecate sha256 (just for test)
        registry.deprecate(
            daid="sha256",  # Can resolve by name
            reason="Quantum vulnerability",
            successor_daid="blake3",
        )

        verifier = DAIDVerifier(
            algorithm_registry=registry,
            min_security_level=64,  # Lower so it passes security check
            warn_on_deprecated=False,
        )
        result = verifier.check_algorithm_status("sha256")

        assert result.verified is True  # Still verifies
        assert result.deprecation_warning is not None
        assert "deprecated" in result.deprecation_warning.lower()


class TestCredentialVerification:
    """Test credential DAID verification."""

    def setup_method(self):
        reset_schema_registry()
        reset_algorithm_daid_registry()

    def test_verify_credential_with_schema(self):
        """Verify credential with valid schema."""
        schema_registry = get_schema_registry()

        schema = schema_registry.register(
            name="test-credential",
            namespace="test",
            version="1.0.0",
            content={"title": "Test Credential", "credentialType": "TestCred"},
        )

        credential = {
            "d": "ECRED_SAID...",
            "s": schema.current_content_said,
            "a": {"name": "Test"},
        }

        verifier = DAIDVerifier(schema_registry=schema_registry)
        result = verifier.verify_credential_daids(credential)

        assert result.verified is True
        assert result.schema_result is not None
        assert result.schema_result.verified is True

    def test_verify_credential_with_invalid_schema(self):
        """Verify credential with invalid schema fails."""
        credential = {
            "d": "ECRED_SAID...",
            "s": "EINVALID_SCHEMA_SAID...",
            "a": {},
        }

        verifier = DAIDVerifier()
        result = verifier.verify_credential_daids(credential)

        assert result.verified is False
        assert len(result.errors) > 0
        assert "schema" in result.errors[0].lower()

    def test_verify_credential_with_algorithm_reference(self):
        """Verify credential that references an algorithm."""
        schema_registry = get_schema_registry()
        algo_registry = get_algorithm_daid_registry()

        schema = schema_registry.register(
            name="hash-cred",
            namespace="test",
            version="1.0.0",
            content={"title": "Hash Credential"},
        )

        credential = {
            "d": "ECRED_SAID...",
            "s": schema.current_content_said,
            "a": {
                "algorithm": "blake3",
            },
        }

        verifier = DAIDVerifier(
            schema_registry=schema_registry,
            algorithm_registry=algo_registry,
        )
        result = verifier.verify_credential_daids(credential)

        assert result.verified is True
        assert len(result.algorithm_results) == 1
        assert result.algorithm_results[0].verified is True


class TestSchemaResolutionForIssuance:
    """Test schema resolution for credential issuance."""

    def setup_method(self):
        reset_schema_registry()

    def test_resolve_schema_for_issuance(self):
        """Can resolve schema SAID for issuance."""
        registry = get_schema_registry()

        schema = registry.register(
            name="issue-test",
            namespace="test",
            version="1.0.0",
            content={"title": "Issue Test"},
        )

        verifier = DAIDVerifier(schema_registry=registry)
        said = verifier.resolve_schema_for_issuance("issue-test")

        assert said is not None
        assert said == schema.current_content_said

    def test_resolve_with_version_pin(self):
        """Can resolve specific version for issuance."""
        registry = get_schema_registry()

        schema = registry.register(
            name="versioned",
            namespace="test",
            version="1.0.0",
            content={"title": "V1"},
        )

        v1_said = schema.current_content_said

        registry.rotate(
            daid=schema.daid,
            new_version="2.0.0",
            new_content={"title": "V2"},
        )

        verifier = DAIDVerifier(schema_registry=registry)

        # Current version
        current_said = verifier.resolve_schema_for_issuance("versioned")
        assert current_said != v1_said  # Should be v2

        # Pinned version
        pinned_said = verifier.resolve_schema_for_issuance("versioned", version="1.0.0")
        assert pinned_said == v1_said


class TestAlgorithmSelection:
    """Test algorithm selection for digest computation."""

    def setup_method(self):
        reset_algorithm_daid_registry()

    def test_get_algorithm_for_digest(self):
        """Can get algorithm for digest computation."""
        verifier = DAIDVerifier()
        algo = verifier.get_algorithm_for_digest("blake3")

        assert algo is not None
        assert algo.name == "blake3"

    def test_follows_deprecation_chain(self):
        """Follows deprecation chain to find active algorithm."""
        registry = get_algorithm_daid_registry()

        # Create a chain: old -> blake3
        old_algo = registry.register(
            name="old-hash",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EOLD_SPEC...",
        )

        blake3 = registry.resolve("blake3")

        # Deprecate old in favor of blake3
        registry.deprecate(
            daid=old_algo.daid,
            reason="Too slow",
            successor_daid=blake3.daid,
        )

        verifier = DAIDVerifier(algorithm_registry=registry)
        algo = verifier.get_algorithm_for_digest("old-hash")

        assert algo is not None
        assert algo.name == "blake3"  # Followed chain


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def setup_method(self):
        reset_schema_registry()
        reset_algorithm_daid_registry()

    def test_verify_schema_function(self):
        """verify_schema convenience function works."""
        registry = get_schema_registry()
        schema = registry.register(
            name="conv-test",
            namespace="test",
            version="1.0.0",
            content={"title": "Conv Test"},
        )

        result = verify_schema(schema.current_content_said)
        assert result.verified is True

    def test_check_algorithm_function(self):
        """check_algorithm convenience function works."""
        result = check_algorithm("blake3")
        assert result.verified is True

    def test_get_schema_said_function(self):
        """get_schema_said_for_issuance convenience function works."""
        registry = get_schema_registry()
        schema = registry.register(
            name="issuance-test",
            namespace="test",
            version="1.0.0",
            content={"title": "Issuance Test"},
        )

        said = get_schema_said_for_issuance("issuance-test")
        assert said == schema.current_content_said
