# -*- encoding: utf-8 -*-
"""
Tests for Algorithm DAID - Governed Cryptographic Algorithms.

Verifies:
- Algorithm registration with DAID computation
- Resolution by DAID, name, and CESR code
- Version rotation (cryptographic agility)
- Deprecation with successor references
- Execution through DAID
"""

import pytest
from keri_sec.algorithms import (
    AlgorithmCategory,
    AlgorithmDAID,
    AlgorithmDAIDRegistry,
    AlgorithmStatus,
    get_algorithm_daid_registry,
    reset_algorithm_daid_registry,
)


class TestAlgorithmDAIDRegistry:
    """Test Algorithm DAID registration and resolution."""

    def setup_method(self):
        """Reset registry before each test."""
        reset_algorithm_daid_registry()

    def test_register_algorithm(self):
        """Registering an algorithm computes DAID."""
        registry = AlgorithmDAIDRegistry()

        algo = registry.register(
            name="test-hash",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ETEST_SPEC_SAID_________________________",
        )

        assert algo.daid.startswith("E")  # SAID prefix
        assert algo.name == "test-hash"
        assert algo.category == AlgorithmCategory.HASH
        assert algo.status == AlgorithmStatus.ACTIVE
        assert len(algo.versions) == 1
        assert algo.current_version.version == "1.0.0"

    def test_resolve_by_daid(self):
        """Can resolve by full DAID or prefix."""
        registry = AlgorithmDAIDRegistry()

        algo = registry.register(
            name="blake3",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EBLAKE3_SPEC____________________________",
        )

        # Full DAID
        resolved = registry.resolve(algo.daid)
        assert resolved is not None
        assert resolved.name == "blake3"

        # Prefix match
        resolved = registry.resolve(algo.daid[:10])
        assert resolved is not None
        assert resolved.name == "blake3"

    def test_resolve_by_name(self):
        """Can resolve by canonical name."""
        registry = AlgorithmDAIDRegistry()

        registry.register(
            name="sha3-256",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ESHA3_SPEC______________________________",
        )

        resolved = registry.resolve("sha3-256")
        assert resolved is not None
        assert resolved.name == "sha3-256"

    def test_resolve_by_cesr_code(self):
        """Can resolve by CESR derivation code."""
        registry = AlgorithmDAIDRegistry()

        registry.register(
            name="blake3",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EBLAKE3_SPEC____________________________",
            cesr_code="E",
        )

        resolved = registry.resolve("E")
        assert resolved is not None
        assert resolved.name == "blake3"

    def test_daid_stable_through_rotation(self):
        """DAID remains stable through version rotations."""
        registry = AlgorithmDAIDRegistry()

        algo = registry.register(
            name="blake3",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EBLAKE3_v1_0____________________________",
        )
        original_daid = algo.daid

        # Rotate to v1.1.0
        registry.rotate(
            daid=algo.daid,
            new_version="1.1.0",
            new_spec_said="EBLAKE3_v1_1____________________________",
        )

        # Rotate to v1.2.0
        registry.rotate(
            daid=algo.daid,
            new_version="1.2.0",
            new_spec_said="EBLAKE3_v1_2____________________________",
        )

        # DAID unchanged
        resolved = registry.resolve(original_daid)
        assert resolved.daid == original_daid
        assert len(resolved.versions) == 3
        assert resolved.current_version.version == "1.2.0"

    def test_version_history_preserved(self):
        """All versions remain accessible after rotations."""
        registry = AlgorithmDAIDRegistry()

        algo = registry.register(
            name="test-algo",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ESPEC_v1_0______________________________",
        )

        registry.rotate(algo.daid, "1.1.0", "ESPEC_v1_1______________________________")
        registry.rotate(algo.daid, "2.0.0", "ESPEC_v2_0______________________________")

        resolved = registry.resolve(algo.daid)
        versions = [v.version for v in resolved.versions]
        assert versions == ["1.0.0", "1.1.0", "2.0.0"]

        # Can access specific version
        v1 = resolved.get_version("1.0.0")
        assert v1 is not None
        assert v1.spec_said == "ESPEC_v1_0______________________________"


class TestCryptographicAgility:
    """Test cryptographic agility scenario - algorithm rotation/deprecation."""

    def setup_method(self):
        reset_algorithm_daid_registry()

    def test_deprecation_with_successor(self):
        """Deprecating algorithm provides successor reference."""
        registry = AlgorithmDAIDRegistry()

        # Register SHA-256
        sha256 = registry.register(
            name="sha256",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ESHA256_SPEC____________________________",
        )

        # Register Blake3 as successor
        blake3 = registry.register(
            name="blake3",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="EBLAKE3_SPEC____________________________",
        )

        # Deprecate SHA-256 in favor of Blake3
        registry.deprecate(
            daid=sha256.daid,
            reason="Quantum vulnerability discovered",
            successor_daid=blake3.daid,
            deadline="2028-01-01T00:00:00Z",
        )

        # Verify deprecation state
        resolved = registry.resolve(sha256.daid)
        assert resolved.is_deprecated
        assert resolved.status == AlgorithmStatus.DEPRECATED
        assert resolved.successor_daid == blake3.daid
        assert resolved.deprecation.reason == "Quantum vulnerability discovered"

        # Can resolve successor
        successor = registry.resolve(resolved.successor_daid)
        assert successor.name == "blake3"
        assert not successor.is_deprecated

    def test_cryptographic_agility_workflow(self):
        """
        Full cryptographic agility scenario:
        1. System uses SHA-256 by DAID
        2. Governance rotates to SHA3-256
        3. System automatically uses new algorithm
        """
        registry = AlgorithmDAIDRegistry()

        # Initial: register hash algorithm
        hash_algo = registry.register(
            name="primary-hash",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ESHA256_SPEC____________________________",
            implementation=lambda d: b"sha256-result",
        )
        daid = hash_algo.daid

        # System uses algorithm by DAID
        algo = registry.resolve(daid)
        result1 = registry.execute(daid, b"test data")
        assert result1 == b"sha256-result"

        # Governance rotates to new implementation
        registry.rotate(
            daid=daid,
            new_version="2.0.0",
            new_spec_said="ESHA3_SPEC______________________________",
            implementation=lambda d: b"sha3-result",
        )

        # Same DAID now resolves to new version
        algo = registry.resolve(daid)
        assert algo.current_version.version == "2.0.0"
        result2 = registry.execute(daid, b"test data")
        assert result2 == b"sha3-result"

        # Old version still accessible if needed
        v1 = algo.get_version("1.0.0")
        assert v1 is not None


class TestBuiltinAlgorithms:
    """Test the built-in core algorithms."""

    def setup_method(self):
        reset_algorithm_daid_registry()

    def test_core_algorithms_registered(self):
        """Core algorithms are pre-registered."""
        registry = get_algorithm_daid_registry()

        # Blake3
        blake3 = registry.resolve("blake3")
        assert blake3 is not None
        assert blake3.cesr_code == "E"

        # SHA3-256
        sha3 = registry.resolve("sha3-256")
        assert sha3 is not None
        assert sha3.cesr_code == "H"

        # SHA-256
        sha256 = registry.resolve("sha256")
        assert sha256 is not None
        assert sha256.cesr_code == "I"

    def test_execute_blake3(self):
        """Can execute Blake3 through DAID."""
        registry = get_algorithm_daid_registry()

        result = registry.execute("blake3", b"test data")
        assert isinstance(result, bytes)
        assert len(result) == 32  # 256-bit output

    def test_execute_sha3_256(self):
        """Can execute SHA3-256 through DAID."""
        registry = get_algorithm_daid_registry()

        result = registry.execute("sha3-256", b"test data")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_execute_sha256(self):
        """Can execute SHA-256 through DAID."""
        registry = get_algorithm_daid_registry()

        result = registry.execute("sha256", b"test data")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_resolve_by_cesr_code(self):
        """Can resolve core algorithms by CESR code."""
        registry = get_algorithm_daid_registry()

        # E = Blake3-256
        algo = registry.resolve("E")
        assert algo.name == "blake3"

        # H = SHA3-256
        algo = registry.resolve("H")
        assert algo.name == "sha3-256"

        # I = SHA2-256
        algo = registry.resolve("I")
        assert algo.name == "sha256"


class TestAlgorithmDAIDSerialization:
    """Test serialization for storage/transmission."""

    def test_to_dict(self):
        """Can serialize AlgorithmDAID to dict."""
        registry = AlgorithmDAIDRegistry()

        algo = registry.register(
            name="test",
            category=AlgorithmCategory.HASH,
            version="1.0.0",
            spec_said="ESPEC_______________________________",
            cesr_code="X",
            security_level=256,
        )

        d = algo.to_dict()
        assert d["name"] == "test"
        assert d["category"] == "hash"
        assert d["cesr_code"] == "X"
        assert d["security_level"] == 256
        assert d["status"] == "active"
        assert d["version_count"] == 1
        assert d["current_version"] == "1.0.0"
