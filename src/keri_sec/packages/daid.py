# -*- encoding: utf-8 -*-
"""
Package DAID - Governed Python Package Identifiers.

Implements DAID pattern for Python packages, enabling:
- Stable identifier through package version releases
- Publisher AID binding (self-sovereign, not PyPI account)
- Content verification via SAIDs
- Supply chain attack mitigation

Usage:
    from keri_sec.packages import PackageDAIDRegistry

    registry = PackageDAIDRegistry()

    # Register a package with publisher AID
    pkg = registry.register(
        name="keri",
        publisher_aid="EPUBLISHER_AID...",
        pypi_name="keri",
        repository_url="https://github.com/WebOfTrust/keripy",
    )

    # Add version with content SAID
    registry.add_version(
        daid=pkg.daid,
        version="1.2.3",
        source_said="ESOURCE_SAID...",
        wheel_saids={"py3": "EWHEEL_SAID..."},
    )

    # Verify installed package
    result = registry.verify_installed("keri", "1.2.3", actual_said="EACTUAL...")
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from keri_governance.cardinal import Operation

from ..attestation import Tier, Attestation, create_attestation, compute_said
from ..base_registry import BaseGAIDRegistry

if TYPE_CHECKING:
    from ..governance.gate import GovernanceGate

logger = logging.getLogger(__name__)


class PackageStatus(Enum):
    """Status of a package in its lifecycle."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    HIJACKED = "hijacked"  # Publisher AID compromised
    SUPERSEDED = "superseded"


@dataclass
class PackageVersion:
    """A specific version of a package."""
    version: str
    source_said: str  # SAID of source tarball
    wheel_saids: Dict[str, str] = field(default_factory=dict)  # platform -> SAID
    release_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    yanked: bool = False
    yank_reason: Optional[str] = None
    attestation: Optional[Attestation] = None

    def get_wheel_said(self, platform: str = "py3") -> Optional[str]:
        """Get wheel SAID for platform."""
        return self.wheel_saids.get(platform)


@dataclass
class DeprecationNotice:
    """Deprecation details for a package."""
    reason: str
    successor_daid: Optional[str] = None
    deadline: Optional[str] = None


@dataclass
class PackageDAID:
    """
    A governed package with DAID identity.

    The DAID prefix remains stable across version releases.
    Publisher AID binding ensures only authorized publishers can add versions.
    """
    daid: str  # Stable identifier (computed from inception)
    name: str  # Canonical package name
    publisher_aid: str  # AID of package publisher
    pypi_name: Optional[str] = None  # Name on PyPI (may differ)
    repository_url: Optional[str] = None
    status: PackageStatus = PackageStatus.ACTIVE
    deprecation: Optional[DeprecationNotice] = None

    # Version chain
    versions: List[PackageVersion] = field(default_factory=list)
    current_version_index: int = -1  # -1 means no versions yet

    @property
    def current_version(self) -> Optional[PackageVersion]:
        """Get current (latest) version."""
        if self.versions and self.current_version_index >= 0:
            return self.versions[self.current_version_index]
        return None

    @property
    def current_source_said(self) -> Optional[str]:
        """Get source SAID of current version."""
        if self.current_version:
            return self.current_version.source_said
        return None

    @property
    def is_deprecated(self) -> bool:
        return self.status in (PackageStatus.DEPRECATED, PackageStatus.SUPERSEDED, PackageStatus.HIJACKED)

    @property
    def successor_daid(self) -> Optional[str]:
        if self.deprecation:
            return self.deprecation.successor_daid
        return None

    def get_version(self, version_str: str) -> Optional[PackageVersion]:
        """Get specific version by version string."""
        for v in self.versions:
            if v.version == version_str:
                return v
        return None

    def get_version_said(self, version_str: str, artifact: str = "source") -> Optional[str]:
        """
        Get content SAID for a specific version.

        Args:
            version_str: Version string (e.g., "1.2.3")
            artifact: "source" for tarball, or platform for wheel (e.g., "py3")

        Returns:
            Content SAID or None if not found
        """
        ver = self.get_version(version_str)
        if ver is None:
            return None

        if artifact == "source":
            return ver.source_said
        return ver.get_wheel_said(artifact)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "daid": self.daid,
            "name": self.name,
            "publisher_aid": self.publisher_aid,
            "pypi_name": self.pypi_name or self.name,
            "repository_url": self.repository_url,
            "status": self.status.value,
            "deprecation": {
                "reason": self.deprecation.reason,
                "successor_daid": self.deprecation.successor_daid,
                "deadline": self.deprecation.deadline,
            } if self.deprecation else None,
            "version_count": len(self.versions),
            "current_version": self.current_version.version if self.current_version else None,
            "current_source_said": self.current_source_said,
        }


@dataclass
class VerificationResult:
    """Result of verifying a package against DAID registry."""
    verified: bool
    package_name: str
    version: Optional[str] = None
    expected_said: Optional[str] = None
    actual_said: Optional[str] = None
    daid: Optional[str] = None
    publisher_aid: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


class PackageDAIDRegistry(BaseGAIDRegistry[PackageDAID]):
    """
    Registry of governed packages with DAID identity.

    Supports:
    - Registration with publisher AID binding
    - Version addition with content SAIDs
    - Verification against installed packages
    - Deprecation with successor references
    - Resolution by DAID, name, or PyPI name
    """

    def __init__(
        self,
        base_path: Optional[Path] = None,
        governance_gate: Optional["GovernanceGate"] = None,
    ):
        super().__init__(governance_gate=governance_gate)
        self._by_pypi_name: Dict[str, str] = {}  # pypi_name -> daid

        self._base_path = base_path or Path.home() / ".keri-sec" / "packages"
        self._base_path.mkdir(parents=True, exist_ok=True)

        # Load existing packages
        self._load_packages()

    # -- Base class hooks --

    def _resolve_extra(self, identifier: str) -> Optional[PackageDAID]:
        if identifier in self._by_pypi_name:
            daid = self._by_pypi_name[identifier]
            return self._entities.get(daid)
        return None

    def _apply_deprecation(self, obj, reason, successor, deadline):
        obj.status = PackageStatus.DEPRECATED
        obj.deprecation = DeprecationNotice(
            reason=reason,
            successor_daid=successor,
            deadline=deadline,
        )

    def _load_packages(self) -> None:
        """Load packages from disk."""
        for pkg_file in self._base_path.glob("*.json"):
            try:
                data = json.loads(pkg_file.read_text())
                versions = [
                    PackageVersion(
                        version=v["version"],
                        source_said=v["source_said"],
                        wheel_saids=v.get("wheel_saids", {}),
                        release_timestamp=v.get("release_timestamp", ""),
                        yanked=v.get("yanked", False),
                        yank_reason=v.get("yank_reason"),
                    )
                    for v in data.get("versions", [])
                ]

                deprecation = None
                if data.get("deprecation"):
                    deprecation = DeprecationNotice(**data["deprecation"])

                pkg = PackageDAID(
                    daid=data["daid"],
                    name=data["name"],
                    publisher_aid=data["publisher_aid"],
                    pypi_name=data.get("pypi_name"),
                    repository_url=data.get("repository_url"),
                    status=PackageStatus(data.get("status", "active")),
                    deprecation=deprecation,
                    versions=versions,
                    current_version_index=data.get("current_version_index", len(versions) - 1),
                )

                self._entities[pkg.daid] = pkg
                self._by_name[pkg.name] = pkg.daid
                if pkg.pypi_name:
                    self._by_pypi_name[pkg.pypi_name] = pkg.daid

            except Exception as e:
                logger.warning(f"Failed to load package {pkg_file}: {e}")

    def _save_package(self, pkg: PackageDAID) -> None:
        """Persist package to disk."""
        data = {
            "daid": pkg.daid,
            "name": pkg.name,
            "publisher_aid": pkg.publisher_aid,
            "pypi_name": pkg.pypi_name,
            "repository_url": pkg.repository_url,
            "status": pkg.status.value,
            "deprecation": {
                "reason": pkg.deprecation.reason,
                "successor_daid": pkg.deprecation.successor_daid,
                "deadline": pkg.deprecation.deadline,
            } if pkg.deprecation else None,
            "versions": [
                {
                    "version": v.version,
                    "source_said": v.source_said,
                    "wheel_saids": v.wheel_saids,
                    "release_timestamp": v.release_timestamp,
                    "yanked": v.yanked,
                    "yank_reason": v.yank_reason,
                }
                for v in pkg.versions
            ],
            "current_version_index": pkg.current_version_index,
        }

        # Use DAID prefix for filename
        safe_daid = pkg.daid.replace("/", "_").replace("+", "-")
        pkg_file = self._base_path / f"{safe_daid[:20]}.json"
        pkg_file.write_text(json.dumps(data, indent=2))

    def register(
        self,
        name: str,
        publisher_aid: str,
        pypi_name: Optional[str] = None,
        repository_url: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> PackageDAID:
        """
        Register a new package, creating its DAID.

        The DAID is computed from the inception data (name, publisher_aid)
        and remains stable across version releases.

        Args:
            name: Canonical package name
            publisher_aid: AID of package publisher
            pypi_name: Name on PyPI (defaults to name)
            repository_url: Repository URL
            issuer_hab: Issuer for attestation

        Returns:
            Registered PackageDAID
        """
        self._enforce(Operation.REGISTER, issuer_hab=issuer_hab)

        pypi_name = pypi_name or name

        # Compute DAID from inception data
        inception = {
            "name": name,
            "publisher_aid": publisher_aid,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        daid = compute_said(inception)

        pkg = PackageDAID(
            daid=daid,
            name=name,
            publisher_aid=publisher_aid,
            pypi_name=pypi_name,
            repository_url=repository_url,
        )

        self._store(daid, name, pkg)
        with self._lock:
            self._by_pypi_name[pypi_name] = daid
            self._save_package(pkg)

        logger.info(f"Registered package DAID: {name} -> {daid[:16]}...")
        return pkg

    def add_version(
        self,
        daid: str,
        version: str,
        source_said: str,
        wheel_saids: Optional[Dict[str, str]] = None,
        issuer_hab: Any = None,
        signer_aid: Optional[str] = None,
    ) -> PackageVersion:
        """
        Add a version to a package.

        Version addition must be authorized by the publisher AID.

        Args:
            daid: Package DAID (or prefix/name)
            version: Version string
            source_said: SAID of source tarball
            wheel_saids: Platform -> wheel SAID mapping
            issuer_hab: Issuer for attestation
            signer_aid: AID signing this version (must match publisher)

        Returns:
            The new PackageVersion

        Raises:
            ValueError: If package not found or unauthorized
        """
        self._enforce(Operation.ROTATE, issuer_hab=issuer_hab)

        pkg = self.resolve(daid)
        if pkg is None:
            raise ValueError(f"Package not found: {daid}")

        # Verify authorization
        if signer_aid and signer_aid != pkg.publisher_aid:
            raise ValueError(
                f"Unauthorized: signer {signer_aid} != publisher {pkg.publisher_aid}"
            )

        # Create version
        new_ver = PackageVersion(
            version=version,
            source_said=source_said,
            wheel_saids=wheel_saids or {},
        )

        # Create attestation if issuer provided
        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "package_version_release",
                        "daid": pkg.daid,
                        "name": pkg.name,
                        "version": version,
                        "source_said": source_said,
                        "wheel_saids": wheel_saids,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Version attestation failed: {e}")

        with self._lock:
            pkg.versions.append(new_ver)
            pkg.current_version_index = len(pkg.versions) - 1
            self._save_package(pkg)

        logger.info(f"Added version {pkg.name}=={version} (source: {source_said[:16]}...)")
        return new_ver

    def verify_package(
        self,
        name: str,
        version: str,
        actual_said: str,
        artifact: str = "source",
    ) -> VerificationResult:
        """
        Verify a package's content SAID against the registry.

        Args:
            name: Package name
            version: Version string
            actual_said: Actually computed SAID
            artifact: "source" or platform for wheel

        Returns:
            VerificationResult with verification status
        """
        pkg = self.resolve(name)

        if pkg is None:
            return VerificationResult(
                verified=False,
                package_name=name,
                version=version,
                actual_said=actual_said,
                error=f"Package not in DAID registry: {name}",
                warnings=["Package verification unavailable - not in registry"],
            )

        expected_said = pkg.get_version_said(version, artifact)

        if expected_said is None:
            return VerificationResult(
                verified=False,
                package_name=name,
                version=version,
                daid=pkg.daid,
                publisher_aid=pkg.publisher_aid,
                actual_said=actual_said,
                error=f"Version {version} not found for {name}",
            )

        warnings = []
        if pkg.is_deprecated:
            warnings.append(
                f"Package {name} is {pkg.status.value}: "
                f"{pkg.deprecation.reason if pkg.deprecation else 'Unknown reason'}"
            )

        verified = actual_said == expected_said

        return VerificationResult(
            verified=verified,
            package_name=name,
            version=version,
            expected_said=expected_said,
            actual_said=actual_said,
            daid=pkg.daid,
            publisher_aid=pkg.publisher_aid,
            status=pkg.status.value,
            error=None if verified else f"SAID mismatch: expected {expected_said[:16]}..., got {actual_said[:16]}...",
            warnings=warnings,
        )

    def deprecate(
        self,
        daid: str,
        reason: str,
        successor_daid: Optional[str] = None,
        deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate a package."""
        super().deprecate(daid, reason, successor=successor_daid, deadline=deadline, issuer_hab=issuer_hab)

        # Persist to disk
        pkg = self.resolve(daid)
        if pkg:
            with self._lock:
                self._save_package(pkg)

    def mark_hijacked(
        self,
        daid: str,
        reason: str,
        safe_versions: Optional[List[str]] = None,
        issuer_hab: Any = None,
    ) -> None:
        """
        Mark a package as hijacked (publisher AID compromised).

        Args:
            daid: Package DAID
            reason: Reason for marking hijacked
            safe_versions: List of versions known to be safe
            issuer_hab: Issuer for attestation
        """
        self._enforce(Operation.REVOKE, issuer_hab=issuer_hab)

        pkg = self.resolve(daid)
        if pkg is None:
            raise ValueError(f"Package not found: {daid}")

        with self._lock:
            pkg.status = PackageStatus.HIJACKED
            pkg.deprecation = DeprecationNotice(
                reason=f"HIJACKED: {reason}",
            )

            # Mark all versions except safe ones as yanked
            if safe_versions:
                for ver in pkg.versions:
                    if ver.version not in safe_versions:
                        ver.yanked = True
                        ver.yank_reason = "Publisher AID compromised"

            self._save_package(pkg)

        logger.error(f"HIJACKED package: {pkg.name} - {reason}")

    def list_packages(self, status: Optional[PackageStatus] = None) -> List[PackageDAID]:
        """List all packages, optionally filtered by status."""
        packages = self.list_all()
        if status:
            packages = [p for p in packages if p.status == status]
        return packages

    def yank_version(
        self,
        daid: str,
        version: str,
        reason: str,
        issuer_hab: Any = None,
    ) -> None:
        """
        Yank a specific version (soft-delete).

        Args:
            daid: Package DAID
            version: Version to yank
            reason: Reason for yanking
            issuer_hab: Issuer for attestation
        """
        pkg = self.resolve(daid)
        if pkg is None:
            raise ValueError(f"Package not found: {daid}")

        ver = pkg.get_version(version)
        if ver is None:
            raise ValueError(f"Version not found: {version}")

        with self._lock:
            ver.yanked = True
            ver.yank_reason = reason
            self._save_package(pkg)

        logger.warning(f"Yanked {pkg.name}=={version}: {reason}")


# Module-level singleton
_registry: Optional[PackageDAIDRegistry] = None
_registry_lock = threading.Lock()


def get_package_daid_registry(
    base_path: Optional[Path] = None,
    governance_gate: Optional["GovernanceGate"] = None,
) -> PackageDAIDRegistry:
    """Get the package DAID registry singleton.

    Args:
        base_path: Path for persisting registry.
        governance_gate: Optional gate to enable cardinal rule enforcement.
    """
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = PackageDAIDRegistry(base_path=base_path)
            if governance_gate is not None:
                _registry.set_governance_gate(governance_gate)
        return _registry


def reset_package_daid_registry():
    """Reset the registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
