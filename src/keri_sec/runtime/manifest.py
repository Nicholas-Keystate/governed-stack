# -*- encoding: utf-8 -*-
"""
RuntimeManifest - Cryptographically attested runtime environment.

A RuntimeManifest captures the complete dependency graph of a KERI runtime:
- Python version
- keripy version (with computed SAID)
- Algorithm GAIDs (cryptographic primitives)
- Protocol GAIDs (CESR, KERI, ACDC versions)

The manifest SAID provides a single identifier that captures the entire
runtime configuration. If any component changes, the SAID changes.

Usage:
    from keri_sec.runtime import RuntimeManifest, capture_current_manifest

    # Capture current environment
    manifest = capture_current_manifest()
    print(f"Runtime SAID: {manifest.said}")

    # Compare against expected
    if manifest.said != EXPECTED_RUNTIME_SAID:
        raise RuntimeError("Environment mismatch!")
"""

import importlib.metadata
import json
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..attestation import compute_said


@dataclass
class RuntimeManifest:
    """
    Cryptographically attested runtime environment specification.

    The manifest captures all dependencies that affect KERI operations.
    Its SAID provides a single verifiable identifier for the entire stack.

    Attributes:
        python_version: Python interpreter version (e.g., "3.12.12")
        keripy_version: keri package version (e.g., "1.3.3")
        keripy_said: SAID computed from keripy package metadata
        hio_version: hio package version
        algorithm_gaids: Mapping of algorithm name to its GAID
        protocol_gaids: Mapping of protocol name to its GAID
        platform_info: Platform details (os, arch, etc.)
        governance_framework_said: Optional framework this runtime complies with
        created_at: ISO timestamp of manifest creation
        issuer_aid: AID that created/attested this manifest
    """
    python_version: str
    keripy_version: str
    keripy_said: str
    hio_version: str
    algorithm_gaids: Dict[str, str] = field(default_factory=dict)
    protocol_gaids: Dict[str, str] = field(default_factory=dict)
    platform_info: Dict[str, str] = field(default_factory=dict)
    governance_framework_said: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    issuer_aid: Optional[str] = None

    # Computed SAID (populated by compute_said())
    _said: Optional[str] = field(default=None, repr=False, compare=False)

    @property
    def said(self) -> str:
        """Get the manifest's SAID, computing if needed."""
        if self._said is None:
            self._said = compute_said(self.to_dict(include_said=False))
        return self._said

    def to_dict(self, include_said: bool = True) -> Dict[str, Any]:
        """Serialize manifest to dict for SAID computation or storage."""
        result = {
            "python_version": self.python_version,
            "keripy_version": self.keripy_version,
            "keripy_said": self.keripy_said,
            "hio_version": self.hio_version,
            "algorithm_gaids": self.algorithm_gaids,
            "protocol_gaids": self.protocol_gaids,
            "platform_info": self.platform_info,
            "created_at": self.created_at,
        }
        if self.governance_framework_said:
            result["governance_framework_said"] = self.governance_framework_said
        if self.issuer_aid:
            result["issuer_aid"] = self.issuer_aid
        if include_said and self._said:
            result["d"] = self._said
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeManifest":
        """Deserialize manifest from dict."""
        manifest = cls(
            python_version=data.get("python_version", ""),
            keripy_version=data.get("keripy_version", ""),
            keripy_said=data.get("keripy_said", ""),
            hio_version=data.get("hio_version", ""),
            algorithm_gaids=data.get("algorithm_gaids", {}),
            protocol_gaids=data.get("protocol_gaids", {}),
            platform_info=data.get("platform_info", {}),
            governance_framework_said=data.get("governance_framework_said"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            issuer_aid=data.get("issuer_aid"),
        )
        if "d" in data:
            manifest._said = data["d"]
        return manifest

    def matches(self, other: "RuntimeManifest", strict: bool = True) -> bool:
        """
        Check if this manifest matches another.

        Args:
            other: Manifest to compare against
            strict: If True, require exact SAID match. If False, compare components.

        Returns:
            True if manifests match
        """
        if strict:
            return self.said == other.said

        # Component-wise comparison (allows timestamp differences)
        return (
            self.python_version == other.python_version
            and self.keripy_version == other.keripy_version
            and self.keripy_said == other.keripy_said
            and self.hio_version == other.hio_version
            and self.algorithm_gaids == other.algorithm_gaids
            and self.protocol_gaids == other.protocol_gaids
        )


def _get_package_version(package: str) -> str:
    """Get installed package version, or 'not_installed' if missing."""
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "not_installed"


def _compute_package_said(package: str) -> str:
    """Compute SAID from package metadata."""
    try:
        version = importlib.metadata.version(package)
        # Include version and location for determinism
        try:
            files = importlib.metadata.files(package)
            file_count = len(files) if files else 0
        except Exception:
            file_count = 0

        metadata = {
            "package": package,
            "version": version,
            "file_count": file_count,
        }
        return compute_said(metadata)
    except Exception:
        return "EUNKNOWN_PACKAGE_SAID"


def _get_platform_info() -> Dict[str, str]:
    """Capture platform details."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_implementation": platform.python_implementation(),
    }


def capture_current_manifest(
    algorithm_registry=None,
    governance_framework_said: Optional[str] = None,
    issuer_aid: Optional[str] = None,
) -> RuntimeManifest:
    """
    Capture a manifest of the current runtime environment.

    Args:
        algorithm_registry: Optional AlgorithmDAIDRegistry to extract GAIDs from
        governance_framework_said: Optional framework this runtime complies with
        issuer_aid: Optional AID creating this manifest

    Returns:
        RuntimeManifest capturing current environment
    """
    # Capture algorithm GAIDs if registry provided
    algorithm_gaids = {}
    if algorithm_registry:
        for algo in algorithm_registry.list_algorithms():
            algorithm_gaids[algo.name] = algo.daid

    # Capture protocol GAIDs (placeholder - would come from protocol registry)
    # TODO: Integrate with protocol GAID registry when available
    protocol_gaids = {
        "cesr": "ECESR_PROTOCOL_GAID_PLACEHOLDER",
        "keri": "EKERI_PROTOCOL_GAID_PLACEHOLDER",
        "acdc": "EACDC_PROTOCOL_GAID_PLACEHOLDER",
    }

    return RuntimeManifest(
        python_version=platform.python_version(),
        keripy_version=_get_package_version("keri"),
        keripy_said=_compute_package_said("keri"),
        hio_version=_get_package_version("hio"),
        algorithm_gaids=algorithm_gaids,
        protocol_gaids=protocol_gaids,
        platform_info=_get_platform_info(),
        governance_framework_said=governance_framework_said,
        issuer_aid=issuer_aid,
    )


def load_manifest(path: str) -> RuntimeManifest:
    """Load manifest from JSON file."""
    with open(path, 'r') as f:
        data = json.load(f)
    return RuntimeManifest.from_dict(data)


def save_manifest(manifest: RuntimeManifest, path: str) -> None:
    """Save manifest to JSON file."""
    with open(path, 'w') as f:
        json.dump(manifest.to_dict(), f, indent=2)
