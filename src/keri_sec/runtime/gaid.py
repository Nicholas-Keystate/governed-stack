# -*- encoding: utf-8 -*-
"""
RuntimeGAID - Governed Runtime Identifier.

A RuntimeGAID extends the GAID pattern to runtime environments:
- Stable identifier through manifest rotations
- Governance rules for allowed component versions
- Deprecation/supersession for runtime migrations

This enables cryptographic verification that a runtime environment
matches an expected configuration, solving "dependency hell" with
cryptographic guarantees.

Usage:
    from keri_sec.runtime import RuntimeGAIDRegistry, RuntimeManifest

    registry = RuntimeGAIDRegistry()

    # Register a governed runtime
    runtime_gaid = registry.register(
        name="euler-production",
        manifest=current_manifest,
        governance_rules={
            "min_keripy_version": "1.2.0",
            "required_algorithms": ["blake3", "ed25519"],
        },
    )

    # Verify current environment
    result = registry.verify(runtime_gaid.gaid)
    if not result.compliant:
        print(f"Violations: {result.violations}")
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ..attestation import Tier, Attestation, create_attestation, compute_said
from .manifest import RuntimeManifest, capture_current_manifest

logger = logging.getLogger(__name__)


class RuntimeStatus(Enum):
    """Status of a runtime GAID."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@dataclass
class GovernanceRules:
    """
    Governance rules for a runtime environment.

    Specifies constraints that a runtime must satisfy to be considered
    compliant with this GAID.
    """
    min_python_version: Optional[str] = None
    max_python_version: Optional[str] = None
    min_keripy_version: Optional[str] = None
    max_keripy_version: Optional[str] = None
    required_algorithms: List[str] = field(default_factory=list)
    forbidden_algorithms: List[str] = field(default_factory=list)
    required_protocol_versions: Dict[str, str] = field(default_factory=dict)
    allowed_platforms: List[str] = field(default_factory=list)  # Empty = any

    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.min_python_version:
            result["min_python_version"] = self.min_python_version
        if self.max_python_version:
            result["max_python_version"] = self.max_python_version
        if self.min_keripy_version:
            result["min_keripy_version"] = self.min_keripy_version
        if self.max_keripy_version:
            result["max_keripy_version"] = self.max_keripy_version
        if self.required_algorithms:
            result["required_algorithms"] = self.required_algorithms
        if self.forbidden_algorithms:
            result["forbidden_algorithms"] = self.forbidden_algorithms
        if self.required_protocol_versions:
            result["required_protocol_versions"] = self.required_protocol_versions
        if self.allowed_platforms:
            result["allowed_platforms"] = self.allowed_platforms
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GovernanceRules":
        return cls(
            min_python_version=data.get("min_python_version"),
            max_python_version=data.get("max_python_version"),
            min_keripy_version=data.get("min_keripy_version"),
            max_keripy_version=data.get("max_keripy_version"),
            required_algorithms=data.get("required_algorithms", []),
            forbidden_algorithms=data.get("forbidden_algorithms", []),
            required_protocol_versions=data.get("required_protocol_versions", {}),
            allowed_platforms=data.get("allowed_platforms", []),
        )


@dataclass
class DeprecationNotice:
    """Deprecation details for a runtime GAID."""
    reason: str
    successor_gaid: Optional[str] = None
    migration_deadline: Optional[str] = None


@dataclass
class RuntimeVersion:
    """A specific version of a runtime configuration."""
    version: str
    manifest_said: str
    manifest: RuntimeManifest
    governance_rules: GovernanceRules
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation: Optional[Attestation] = None


@dataclass
class RuntimeGAID:
    """
    A governed runtime with GAID identity.

    The GAID remains stable across manifest rotations (version updates).
    Each rotation adds a new RuntimeVersion to the history.
    """
    gaid: str  # Stable identifier (computed from inception)
    name: str
    description: str = ""
    status: RuntimeStatus = RuntimeStatus.ACTIVE
    deprecation: Optional[DeprecationNotice] = None

    # Version chain
    versions: List[RuntimeVersion] = field(default_factory=list)
    current_version_index: int = 0

    @property
    def current_version(self) -> Optional[RuntimeVersion]:
        """Get current (latest) version."""
        if self.versions:
            return self.versions[self.current_version_index]
        return None

    @property
    def current_manifest(self) -> Optional[RuntimeManifest]:
        """Get current manifest."""
        if self.current_version:
            return self.current_version.manifest
        return None

    @property
    def current_rules(self) -> Optional[GovernanceRules]:
        """Get current governance rules."""
        if self.current_version:
            return self.current_version.governance_rules
        return None

    @property
    def is_deprecated(self) -> bool:
        return self.status in (RuntimeStatus.DEPRECATED, RuntimeStatus.SUPERSEDED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gaid": self.gaid,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "deprecation": {
                "reason": self.deprecation.reason,
                "successor_gaid": self.deprecation.successor_gaid,
                "migration_deadline": self.deprecation.migration_deadline,
            } if self.deprecation else None,
            "version_count": len(self.versions),
            "current_version": self.current_version.version if self.current_version else None,
            "current_manifest_said": self.current_version.manifest_said if self.current_version else None,
        }


@dataclass
class VerificationResult:
    """Result of runtime verification against a GAID."""
    compliant: bool
    gaid: str
    runtime_said: str
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliant": self.compliant,
            "gaid": self.gaid,
            "runtime_said": self.runtime_said,
            "violations": self.violations,
            "warnings": self.warnings,
            "checked_at": self.checked_at,
        }


class RuntimeGAIDRegistry:
    """
    Registry of governed runtime configurations.

    Supports:
    - Registration with computed GAID
    - Manifest rotation (append-only version chain)
    - Governance rule enforcement
    - Current environment verification
    """

    def __init__(self, algorithm_registry=None):
        """
        Initialize registry.

        Args:
            algorithm_registry: Optional AlgorithmDAIDRegistry for algorithm lookups
        """
        self._runtimes: Dict[str, RuntimeGAID] = {}  # gaid -> RuntimeGAID
        self._by_name: Dict[str, str] = {}  # name -> gaid
        self._algorithm_registry = algorithm_registry
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        manifest: RuntimeManifest,
        governance_rules: Optional[GovernanceRules] = None,
        version: str = "1.0.0",
        description: str = "",
        issuer_hab: Any = None,
    ) -> RuntimeGAID:
        """
        Register a new governed runtime, creating its GAID.

        Args:
            name: Runtime configuration name (e.g., "euler-production")
            manifest: Initial RuntimeManifest
            governance_rules: Optional governance constraints
            version: Initial version string
            description: Human-readable description
            issuer_hab: Issuer for attestation

        Returns:
            Registered RuntimeGAID
        """
        rules = governance_rules or GovernanceRules()

        # Compute GAID from inception data
        inception = {
            "name": name,
            "initial_manifest_said": manifest.said,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        gaid = compute_said(inception)

        # Create initial version
        initial_version = RuntimeVersion(
            version=version,
            manifest_said=manifest.said,
            manifest=manifest,
            governance_rules=rules,
        )

        # Create attestation if issuer provided
        if issuer_hab:
            try:
                initial_version.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "runtime_registration",
                        "gaid": gaid,
                        "name": name,
                        "version": version,
                        "manifest_said": manifest.said,
                        "rules": rules.to_dict(),
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Attestation failed: {e}")

        runtime = RuntimeGAID(
            gaid=gaid,
            name=name,
            description=description,
            versions=[initial_version],
        )

        with self._lock:
            self._runtimes[gaid] = runtime
            self._by_name[name] = gaid

        logger.info(f"Registered runtime GAID: {name} -> {gaid[:16]}...")
        return runtime

    def resolve(self, identifier: str) -> Optional[RuntimeGAID]:
        """
        Resolve runtime by GAID or name.

        Args:
            identifier: GAID prefix or name

        Returns:
            RuntimeGAID or None if not found
        """
        with self._lock:
            # Try exact GAID match
            if identifier in self._runtimes:
                return self._runtimes[identifier]

            # Try GAID prefix match
            for gaid, runtime in self._runtimes.items():
                if gaid.startswith(identifier):
                    return runtime

            # Try name lookup
            if identifier in self._by_name:
                gaid = self._by_name[identifier]
                return self._runtimes.get(gaid)

        return None

    def rotate(
        self,
        gaid: str,
        new_manifest: RuntimeManifest,
        new_version: str,
        new_rules: Optional[GovernanceRules] = None,
        issuer_hab: Any = None,
    ) -> RuntimeVersion:
        """
        Rotate a runtime to a new manifest.

        Args:
            gaid: Runtime GAID
            new_manifest: New RuntimeManifest
            new_version: New version string
            new_rules: Optional new governance rules (inherits current if None)
            issuer_hab: Issuer for attestation

        Returns:
            The new RuntimeVersion
        """
        runtime = self.resolve(gaid)
        if runtime is None:
            raise ValueError(f"Runtime not found: {gaid}")

        rules = new_rules or runtime.current_rules or GovernanceRules()

        new_ver = RuntimeVersion(
            version=new_version,
            manifest_said=new_manifest.said,
            manifest=new_manifest,
            governance_rules=rules,
        )

        # Create rotation attestation
        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "runtime_rotation",
                        "gaid": runtime.gaid,
                        "previous_version": runtime.current_version.version,
                        "new_version": new_version,
                        "previous_manifest_said": runtime.current_version.manifest_said,
                        "new_manifest_said": new_manifest.said,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Rotation attestation failed: {e}")

        with self._lock:
            runtime.versions.append(new_ver)
            runtime.current_version_index = len(runtime.versions) - 1

        logger.info(f"Rotated {runtime.name}: {runtime.versions[-2].version} -> {new_version}")
        return new_ver

    def verify(
        self,
        gaid: str,
        current_manifest: Optional[RuntimeManifest] = None,
    ) -> VerificationResult:
        """
        Verify current environment against a runtime GAID.

        Args:
            gaid: Runtime GAID to verify against
            current_manifest: Optional manifest (captures current if None)

        Returns:
            VerificationResult with compliance status
        """
        runtime = self.resolve(gaid)
        if runtime is None:
            return VerificationResult(
                compliant=False,
                gaid=gaid,
                runtime_said="",
                violations=[f"Runtime GAID not found: {gaid}"],
            )

        # Capture current environment if not provided
        if current_manifest is None:
            current_manifest = capture_current_manifest(
                algorithm_registry=self._algorithm_registry
            )

        violations = []
        warnings = []
        rules = runtime.current_rules

        if rules:
            # Check Python version
            if rules.min_python_version:
                if not self._version_gte(current_manifest.python_version, rules.min_python_version):
                    violations.append(
                        f"Python {current_manifest.python_version} < required {rules.min_python_version}"
                    )

            if rules.max_python_version:
                if not self._version_lte(current_manifest.python_version, rules.max_python_version):
                    violations.append(
                        f"Python {current_manifest.python_version} > allowed {rules.max_python_version}"
                    )

            # Check keripy version
            if rules.min_keripy_version:
                if not self._version_gte(current_manifest.keripy_version, rules.min_keripy_version):
                    violations.append(
                        f"keripy {current_manifest.keripy_version} < required {rules.min_keripy_version}"
                    )

            if rules.max_keripy_version:
                if not self._version_lte(current_manifest.keripy_version, rules.max_keripy_version):
                    violations.append(
                        f"keripy {current_manifest.keripy_version} > allowed {rules.max_keripy_version}"
                    )

            # Check required algorithms
            for algo in rules.required_algorithms:
                if algo not in current_manifest.algorithm_gaids:
                    violations.append(f"Required algorithm missing: {algo}")

            # Check forbidden algorithms
            for algo in rules.forbidden_algorithms:
                if algo in current_manifest.algorithm_gaids:
                    violations.append(f"Forbidden algorithm present: {algo}")

            # Check platform
            if rules.allowed_platforms:
                platform_system = current_manifest.platform_info.get("system", "")
                if platform_system not in rules.allowed_platforms:
                    violations.append(
                        f"Platform {platform_system} not in allowed: {rules.allowed_platforms}"
                    )

        # Check deprecation
        if runtime.is_deprecated:
            warnings.append(
                f"Runtime GAID is deprecated: {runtime.deprecation.reason if runtime.deprecation else 'No reason given'}"
            )
            if runtime.deprecation and runtime.deprecation.successor_gaid:
                warnings.append(f"Migrate to: {runtime.deprecation.successor_gaid}")

        return VerificationResult(
            compliant=len(violations) == 0,
            gaid=gaid,
            runtime_said=current_manifest.said,
            violations=violations,
            warnings=warnings,
        )

    def _version_gte(self, actual: str, required: str) -> bool:
        """Check if actual version >= required version."""
        try:
            from packaging.version import Version
            return Version(actual) >= Version(required)
        except Exception:
            # Fallback to string comparison
            return actual >= required

    def _version_lte(self, actual: str, allowed: str) -> bool:
        """Check if actual version <= allowed version."""
        try:
            from packaging.version import Version
            return Version(actual) <= Version(allowed)
        except Exception:
            return actual <= allowed

    def deprecate(
        self,
        gaid: str,
        reason: str,
        successor_gaid: Optional[str] = None,
        migration_deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate a runtime GAID."""
        runtime = self.resolve(gaid)
        if runtime is None:
            raise ValueError(f"Runtime not found: {gaid}")

        with self._lock:
            runtime.status = RuntimeStatus.DEPRECATED
            runtime.deprecation = DeprecationNotice(
                reason=reason,
                successor_gaid=successor_gaid,
                migration_deadline=migration_deadline,
            )

        if issuer_hab:
            try:
                create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "runtime_deprecation",
                        "gaid": runtime.gaid,
                        "name": runtime.name,
                        "reason": reason,
                        "successor_gaid": successor_gaid,
                        "migration_deadline": migration_deadline,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Deprecation attestation failed: {e}")

        logger.warning(f"Deprecated runtime: {runtime.name} - {reason}")

    def list_runtimes(self, include_deprecated: bool = False) -> List[RuntimeGAID]:
        """List all registered runtimes."""
        with self._lock:
            runtimes = list(self._runtimes.values())
            if not include_deprecated:
                runtimes = [r for r in runtimes if not r.is_deprecated]
            return runtimes


# Module-level singleton
_registry: Optional[RuntimeGAIDRegistry] = None
_registry_lock = threading.Lock()


def get_runtime_gaid_registry(algorithm_registry=None) -> RuntimeGAIDRegistry:
    """Get the runtime GAID registry singleton."""
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = RuntimeGAIDRegistry(algorithm_registry=algorithm_registry)
        return _registry


def reset_runtime_gaid_registry():
    """Reset the registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
