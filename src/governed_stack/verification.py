# -*- encoding: utf-8 -*-
"""
Environment Verification - End-to-End Verifiable Installations

Principle: SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.

This module verifies that installed packages match the InstallationCredential.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from keri.core import coring


@dataclass
class PackageMismatch:
    """Record of a package that doesn't match the credential."""
    name: str
    expected_version: str
    actual_version: Optional[str]
    reason: str  # "missing", "version_mismatch", "extra"


@dataclass
class VerificationResult:
    """Result of environment verification."""
    verified: bool
    credential_said: str
    stack_said: str
    lock_said: str
    python_verified: bool
    packages_verified: int
    mismatches: List[PackageMismatch] = field(default_factory=list)
    tel_status: str = "unknown"  # "valid", "revoked", "unknown"
    error: str = ""
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class InstallationCredential:
    """Parsed installation credential."""
    said: str
    issuer: str
    stack_said: str
    lock_said: str
    python_version: str
    platform: str
    venv_path: str
    packages: List[Tuple[str, str]]  # (name, version)
    issued_at: datetime
    registry_said: Optional[str] = None

    @classmethod
    def load(cls, path: Path) -> Optional[InstallationCredential]:
        """Load credential from file."""
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text())
            attrs = data.get("a", {})

            packages = [
                (p["name"], p["version"])
                for p in attrs.get("packages", [])
            ]

            return cls(
                said=data.get("d", ""),
                issuer=data.get("i", ""),
                stack_said=attrs.get("stack_said", ""),
                lock_said=attrs.get("lock_said", ""),
                python_version=attrs.get("python_version", ""),
                platform=attrs.get("platform", ""),
                venv_path=attrs.get("venv_path", ".venv"),
                packages=packages,
                issued_at=datetime.fromisoformat(attrs.get("dt", "2000-01-01T00:00:00+00:00")),
                registry_said=data.get("ri"),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            return None


def get_installed_packages(venv_path: Path) -> dict[str, str]:
    """Get installed packages from venv.

    Supports both pip-managed and UV-managed venvs.
    """
    python = venv_path / "bin" / "python"
    if not python.exists():
        python = venv_path / "Scripts" / "python.exe"  # Windows

    if not python.exists():
        return {}

    # Try UV first (works for UV-managed venvs without pip)
    try:
        result = subprocess.run(
            ["uv", "pip", "list", "--format=json", "--python", str(python)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            return {p["name"].lower(): p["version"] for p in packages}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    # Fallback to pip
    try:
        result = subprocess.run(
            [str(python), "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {}

        packages = json.loads(result.stdout)
        return {p["name"].lower(): p["version"] for p in packages}
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}


def get_python_version(venv_path: Path) -> Optional[str]:
    """Get Python version from venv."""
    python = venv_path / "bin" / "python"
    if not python.exists():
        python = venv_path / "Scripts" / "python.exe"  # Windows

    if not python.exists():
        return None

    try:
        result = subprocess.run(
            [str(python), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None

        # "Python 3.12.12" -> "3.12.12"
        return result.stdout.strip().split()[-1]
    except subprocess.TimeoutExpired:
        return None


def verify_tel_status(registry_said: str, credential_said: str) -> str:
    """
    Verify credential TEL status.

    Returns: "valid", "revoked", or "unknown"
    """
    # TODO: Implement actual TEL verification via keripy
    # For now, return unknown (allows operation but logs warning)
    try:
        from keri.vdr import verifying
        # Would need access to Habery and registry
        # verifier = verifying.Verifier(hby=hby, rgy=rgy)
        # state = verifier.verify(credential_said)
        return "unknown"
    except ImportError:
        return "unknown"


def verify_environment(
    credential_path: Optional[Path] = None,
    venv_path: Optional[Path] = None,
    strict: bool = True,
) -> VerificationResult:
    """
    Verify installed environment matches InstallationCredential.

    Args:
        credential_path: Path to installation credential (default: .governed/installation.json)
        venv_path: Path to venv (default: from credential or .venv)
        strict: If True, fail on any mismatch. If False, allow extra packages.

    Returns:
        VerificationResult with verification status and any mismatches.
    """
    # Default paths
    if credential_path is None:
        credential_path = Path(".governed/installation.json")

    # Load credential
    cred = InstallationCredential.load(credential_path)
    if cred is None:
        return VerificationResult(
            verified=False,
            credential_said="",
            stack_said="",
            lock_said="",
            python_verified=False,
            packages_verified=0,
            error=f"No installation credential found at {credential_path}",
        )

    # Determine venv path
    if venv_path is None:
        venv_path = Path(cred.venv_path)

    # Verify TEL status
    tel_status = "unknown"
    if cred.registry_said:
        tel_status = verify_tel_status(cred.registry_said, cred.said)
        if tel_status == "revoked":
            return VerificationResult(
                verified=False,
                credential_said=cred.said,
                stack_said=cred.stack_said,
                lock_said=cred.lock_said,
                python_verified=False,
                packages_verified=0,
                tel_status="revoked",
                error="Installation credential has been revoked",
            )

    # Verify Python version
    actual_python = get_python_version(venv_path)
    python_verified = actual_python == cred.python_version
    mismatches: List[PackageMismatch] = []

    if not python_verified:
        mismatches.append(PackageMismatch(
            name="python",
            expected_version=cred.python_version,
            actual_version=actual_python,
            reason="version_mismatch",
        ))

    # Get installed packages
    installed = get_installed_packages(venv_path)

    # Verify each expected package
    packages_verified = 0
    for name, expected_version in cred.packages:
        normalized_name = name.lower().replace("-", "_").replace(".", "_")
        actual_version = None

        # Try exact match first, then normalized
        for installed_name, installed_version in installed.items():
            if installed_name.lower() == name.lower():
                actual_version = installed_version
                break
            normalized_installed = installed_name.replace("-", "_").replace(".", "_")
            if normalized_installed == normalized_name:
                actual_version = installed_version
                break

        if actual_version is None:
            mismatches.append(PackageMismatch(
                name=name,
                expected_version=expected_version,
                actual_version=None,
                reason="missing",
            ))
        elif actual_version != expected_version:
            mismatches.append(PackageMismatch(
                name=name,
                expected_version=expected_version,
                actual_version=actual_version,
                reason="version_mismatch",
            ))
        else:
            packages_verified += 1

    # Check for extra packages (in strict mode)
    if strict:
        expected_names = {n.lower() for n, _ in cred.packages}
        # Standard packages to ignore
        ignore = {"pip", "setuptools", "wheel", "uv"}
        for name in installed:
            if name.lower() not in expected_names and name.lower() not in ignore:
                mismatches.append(PackageMismatch(
                    name=name,
                    expected_version="(not expected)",
                    actual_version=installed[name],
                    reason="extra",
                ))

    verified = len(mismatches) == 0

    return VerificationResult(
        verified=verified,
        credential_said=cred.said,
        stack_said=cred.stack_said,
        lock_said=cred.lock_said,
        python_verified=python_verified,
        packages_verified=packages_verified,
        mismatches=mismatches,
        tel_status=tel_status,
        error="" if verified else f"{len(mismatches)} package(s) don't match credential",
    )


def verify_or_fail(
    credential_path: Optional[Path] = None,
    venv_path: Optional[Path] = None,
    strict: bool = True,
) -> None:
    """
    Verify environment and raise if verification fails.

    Use in conftest.py or script entry points.
    """
    result = verify_environment(credential_path, venv_path, strict)

    if not result.verified:
        error_lines = [
            "Environment verification FAILED",
            f"  Credential: {result.credential_said or '(none)'}",
            f"  Stack: {result.stack_said or '(none)'}",
            f"  TEL Status: {result.tel_status}",
            "",
        ]

        if result.mismatches:
            error_lines.append("Mismatches:")
            for m in result.mismatches:
                if m.reason == "missing":
                    error_lines.append(f"  - {m.name}: MISSING (expected {m.expected_version})")
                elif m.reason == "version_mismatch":
                    error_lines.append(f"  - {m.name}: {m.actual_version} (expected {m.expected_version})")
                elif m.reason == "extra":
                    error_lines.append(f"  - {m.name}: {m.actual_version} (not in credential)")

        error_lines.extend([
            "",
            "Run: governed-stack install <stack-said> --venv --credential",
        ])

        raise EnvironmentError("\n".join(error_lines))


class EnvironmentVerificationPlugin:
    """Pytest plugin for environment verification."""

    def __init__(self, credential_path: Optional[Path] = None, strict: bool = True):
        self.credential_path = credential_path
        self.strict = strict

    def pytest_configure(self, config):
        """Verify environment before test collection."""
        try:
            verify_or_fail(self.credential_path, strict=self.strict)
        except EnvironmentError as e:
            import pytest
            pytest.exit(str(e), returncode=1)


# For use in conftest.py:
# from governed_stack.verification import EnvironmentVerificationPlugin
# def pytest_configure(config):
#     plugin = EnvironmentVerificationPlugin()
#     plugin.pytest_configure(config)
