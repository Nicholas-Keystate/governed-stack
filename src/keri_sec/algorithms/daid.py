# -*- encoding: utf-8 -*-
"""
Algorithm DAID - Governed Algorithm Identifiers.

Implements DAID pattern for cryptographic algorithms, enabling:
- Stable identifier through version rotations
- Governed deprecation with successor references
- Cryptographic agility via resolution

Usage:
    from keri_sec.algorithms import AlgorithmDAIDRegistry

    registry = AlgorithmDAIDRegistry()

    # Resolve by DAID prefix (stable)
    blake3 = registry.resolve("EDALGO_BLAKE3")

    # Check deprecation status
    if blake3.is_deprecated:
        successor = registry.resolve(blake3.successor_daid)

    # Rotate to new version
    registry.rotate(
        daid="EDALGO_BLAKE3",
        new_spec_said="ENEW_SPEC...",
        version="1.3.0",
        issuer_hab=governance_hab,
    )
"""

import hashlib
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from keri_governance.cardinal import Operation

from ..attestation import Tier, Attestation, create_attestation, compute_said
from ..base_registry import BaseGAIDRegistry

if TYPE_CHECKING:
    from ..governance.gate import GovernanceGate

logger = logging.getLogger(__name__)


class AlgorithmCategory(Enum):
    """Categories of cryptographic algorithms."""
    HASH = "hash"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    KDF = "kdf"
    MAC = "mac"


class AlgorithmStatus(Enum):
    """Status of an algorithm in its lifecycle."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@dataclass
class DeprecationNotice:
    """Deprecation details for an algorithm."""
    reason: str
    successor_daid: Optional[str] = None
    deadline: Optional[str] = None


@dataclass
class AlgorithmVersion:
    """A specific version of an algorithm."""
    version: str
    spec_said: str
    implementation: Optional[Callable] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation: Optional[Attestation] = None


@dataclass
class AlgorithmDAID:
    """
    A governed algorithm with DAID identity.

    The DAID prefix remains stable across version rotations.
    Each rotation adds a new AlgorithmVersion to the history.
    """
    daid: str  # Stable identifier (computed from inception)
    name: str
    category: AlgorithmCategory
    cesr_code: Optional[str] = None
    security_level: int = 256
    status: AlgorithmStatus = AlgorithmStatus.ACTIVE
    deprecation: Optional[DeprecationNotice] = None

    # Version chain
    versions: List[AlgorithmVersion] = field(default_factory=list)
    current_version_index: int = 0

    @property
    def current_version(self) -> Optional[AlgorithmVersion]:
        """Get current (latest) version."""
        if self.versions:
            return self.versions[self.current_version_index]
        return None

    @property
    def is_deprecated(self) -> bool:
        return self.status in (AlgorithmStatus.DEPRECATED, AlgorithmStatus.SUPERSEDED)

    @property
    def successor_daid(self) -> Optional[str]:
        if self.deprecation:
            return self.deprecation.successor_daid
        return None

    def get_version(self, version_str: str) -> Optional[AlgorithmVersion]:
        """Get specific version by version string."""
        for v in self.versions:
            if v.version == version_str:
                return v
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "daid": self.daid,
            "name": self.name,
            "category": self.category.value,
            "cesr_code": self.cesr_code,
            "security_level": self.security_level,
            "status": self.status.value,
            "deprecation": {
                "reason": self.deprecation.reason,
                "successor_daid": self.deprecation.successor_daid,
                "deadline": self.deprecation.deadline,
            } if self.deprecation else None,
            "version_count": len(self.versions),
            "current_version": self.current_version.version if self.current_version else None,
        }


class AlgorithmDAIDRegistry(BaseGAIDRegistry[AlgorithmDAID]):
    """
    Registry of governed algorithms with DAID identity.

    Supports:
    - Registration with computed DAID
    - Version rotation (append-only)
    - Deprecation with successor references
    - Resolution by DAID prefix, name, or CESR code
    """

    def __init__(self, governance_gate: Optional["GovernanceGate"] = None):
        super().__init__(governance_gate=governance_gate)
        self._by_cesr_code: Dict[str, str] = {}  # code -> daid

    # -- Base class hooks --

    def _resolve_extra(self, identifier: str) -> Optional[AlgorithmDAID]:
        if identifier in self._by_cesr_code:
            daid = self._by_cesr_code[identifier]
            return self._entities.get(daid)
        return None

    def _apply_deprecation(self, obj, reason, successor, deadline):
        obj.status = AlgorithmStatus.DEPRECATED
        obj.deprecation = DeprecationNotice(
            reason=reason,
            successor_daid=successor,
            deadline=deadline,
        )

    # -- Domain methods --

    def register(
        self,
        name: str,
        category: AlgorithmCategory,
        version: str,
        spec_said: str,
        implementation: Optional[Callable] = None,
        cesr_code: Optional[str] = None,
        security_level: int = 256,
        issuer_hab: Any = None,
    ) -> AlgorithmDAID:
        """
        Register a new algorithm, creating its DAID.

        The DAID is computed from the inception data (name, category, initial spec)
        and remains stable across future rotations.
        """
        self._enforce(Operation.REGISTER, issuer_hab=issuer_hab)

        # Compute DAID from inception data
        inception = {
            "name": name,
            "category": category.value,
            "initial_spec_said": spec_said,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        daid = compute_said(inception)

        # Create initial version
        initial_version = AlgorithmVersion(
            version=version,
            spec_said=spec_said,
            implementation=implementation,
        )

        # Create attestation if issuer provided
        if issuer_hab:
            try:
                initial_version.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "algorithm_registration",
                        "daid": daid,
                        "name": name,
                        "version": version,
                        "spec_said": spec_said,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Attestation failed: {e}")

        algorithm = AlgorithmDAID(
            daid=daid,
            name=name,
            category=category,
            cesr_code=cesr_code,
            security_level=security_level,
            versions=[initial_version],
        )

        self._store(daid, name, algorithm)
        with self._lock:
            if cesr_code:
                self._by_cesr_code[cesr_code] = daid

        logger.info(f"Registered algorithm DAID: {name} -> {daid[:16]}...")
        return algorithm

    def rotate(
        self,
        daid: str,
        new_version: str,
        new_spec_said: str,
        implementation: Optional[Callable] = None,
        issuer_hab: Any = None,
    ) -> AlgorithmVersion:
        """
        Rotate an algorithm to a new version.

        This is an append-only operation - old versions remain accessible.
        """
        self._enforce(Operation.ROTATE, issuer_hab=issuer_hab)

        algorithm = self.resolve(daid)
        if algorithm is None:
            raise ValueError(f"Algorithm not found: {daid}")

        # Create new version
        new_ver = AlgorithmVersion(
            version=new_version,
            spec_said=new_spec_said,
            implementation=implementation or algorithm.current_version.implementation,
        )

        # Create rotation attestation
        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "algorithm_rotation",
                        "daid": algorithm.daid,
                        "previous_version": algorithm.current_version.version,
                        "new_version": new_version,
                        "previous_spec_said": algorithm.current_version.spec_said,
                        "new_spec_said": new_spec_said,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Rotation attestation failed: {e}")

        with self._lock:
            algorithm.versions.append(new_ver)
            algorithm.current_version_index = len(algorithm.versions) - 1

        logger.info(f"Rotated {algorithm.name}: {algorithm.versions[-2].version} -> {new_version}")
        return new_ver

    def deprecate(
        self,
        daid: str,
        reason: str,
        successor_daid: Optional[str] = None,
        deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate an algorithm."""
        super().deprecate(daid, reason, successor=successor_daid, deadline=deadline, issuer_hab=issuer_hab)

        # Create deprecation attestation
        algorithm = self.resolve(daid)
        if issuer_hab and algorithm:
            try:
                create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "algorithm_deprecation",
                        "daid": algorithm.daid,
                        "name": algorithm.name,
                        "reason": reason,
                        "successor_daid": successor_daid,
                        "deadline": deadline,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Deprecation attestation failed: {e}")

    def list_algorithms(self, category: Optional[AlgorithmCategory] = None) -> List[AlgorithmDAID]:
        """List all algorithms, optionally filtered by category."""
        algos = self.list_all()
        if category:
            algos = [a for a in algos if a.category == category]
        return algos

    def execute(
        self,
        daid: str,
        data: bytes,
        version: Optional[str] = None,
    ) -> bytes:
        """
        Execute an algorithm's implementation.

        Args:
            daid: Algorithm DAID
            data: Input data
            version: Specific version (default: current)

        Returns:
            Algorithm output
        """
        algorithm = self.resolve(daid)
        if algorithm is None:
            raise ValueError(f"Algorithm not found: {daid}")

        if algorithm.is_deprecated:
            logger.warning(
                f"Algorithm {algorithm.name} is deprecated: {algorithm.deprecation.reason}. "
                f"Consider migrating to {algorithm.successor_daid}"
            )

        # Get implementation
        if version:
            ver = algorithm.get_version(version)
            if ver is None:
                raise ValueError(f"Version not found: {version}")
        else:
            ver = algorithm.current_version

        if ver.implementation is None:
            raise ValueError(f"No implementation for {algorithm.name} v{ver.version}")

        return ver.implementation(data)


# Built-in algorithm implementations
def _blake3_hash(data: bytes) -> bytes:
    """Blake3 hash implementation."""
    try:
        import blake3
        return blake3.blake3(data).digest()
    except ImportError:
        # Fallback to hashlib if blake3 not installed
        import hashlib
        return hashlib.blake2b(data, digest_size=32).digest()


def _sha3_256_hash(data: bytes) -> bytes:
    """SHA3-256 hash implementation."""
    return hashlib.sha3_256(data).digest()


def _sha256_hash(data: bytes) -> bytes:
    """SHA-256 hash implementation."""
    return hashlib.sha256(data).digest()


# Module-level singleton
_registry: Optional[AlgorithmDAIDRegistry] = None
_registry_lock = threading.Lock()


def get_algorithm_daid_registry(
    governance_gate: Optional["GovernanceGate"] = None,
) -> AlgorithmDAIDRegistry:
    """Get the algorithm DAID registry singleton with core algorithms registered.

    Args:
        governance_gate: Optional gate to enable cardinal rule enforcement.
            Applied after genesis registrations (two-phase lifecycle).
    """
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = AlgorithmDAIDRegistry()  # ungoverned genesis

            # Register core cryptographic algorithms
            _registry.register(
                name="blake3",
                category=AlgorithmCategory.HASH,
                version="1.3.0",
                spec_said="EHsiY2F0ZWdvcnkiOiJoYXNoIiwibmFtZSI6IkJMQUtF",
                implementation=_blake3_hash,
                cesr_code="E",  # CESR code for Blake3-256
                security_level=256,
            )

            _registry.register(
                name="sha3-256",
                category=AlgorithmCategory.HASH,
                version="1.0.0",
                spec_said="EHsiY2F0ZWdvcnkiOiJoYXNoIiwibmFtZSI6IlNIQTMt",
                implementation=_sha3_256_hash,
                cesr_code="H",  # CESR code for SHA3-256
                security_level=256,
            )

            _registry.register(
                name="sha256",
                category=AlgorithmCategory.HASH,
                version="1.0.0",
                spec_said="EHsiY2F0ZWdvcnkiOiJoYXNoIiwibmFtZSI6IlNIQS0y",
                implementation=_sha256_hash,
                cesr_code="I",  # CESR code for SHA2-256
                security_level=128,  # Quantum security level
            )

            # Enable governance after genesis registrations
            if governance_gate is not None:
                _registry.set_governance_gate(governance_gate)

        return _registry


def reset_algorithm_daid_registry():
    """Reset the registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
