# -*- encoding: utf-8 -*-
"""
SAIDified Lock File Generation

Phase 1: Lock File SAIDs
- Resolve dependencies to exact versions
- Compute SAID for each package wheel
- Compute overall lock file SAID
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from keri.core import coring


@dataclass
class ResolvedPackage:
    """A resolved package with exact version and SAID."""
    name: str
    version: str
    source: str = "pypi"  # pypi, git, local, url
    wheel_said: str = ""  # SAID of wheel content (if available)
    source_url: str = ""
    dependencies: List[str] = field(default_factory=list)


@dataclass
class LockFile:
    """SAIDified lock file."""
    said: str
    governed_by: str  # Stack SAID
    resolved_at: datetime
    resolver: str
    python_version: str
    platform: str
    packages: List[ResolvedPackage]

    def to_dict(self) -> dict:
        """Serialize to dict for JSON."""
        return {
            "d": self.said,
            "v": "GS10JSON000000_",
            "governed_by": self.governed_by,
            "resolved_at": self.resolved_at.isoformat(),
            "resolver": self.resolver,
            "python": {
                "version": self.python_version,
                "platform": self.platform,
            },
            "packages": [
                {
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "wheel_said": p.wheel_said,
                    "source_url": p.source_url,
                    "dependencies": p.dependencies,
                }
                for p in sorted(self.packages, key=lambda x: x.name.lower())
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict) -> LockFile:
        """Deserialize from dict."""
        packages = [
            ResolvedPackage(
                name=p["name"],
                version=p["version"],
                source=p.get("source", "pypi"),
                wheel_said=p.get("wheel_said", ""),
                source_url=p.get("source_url", ""),
                dependencies=p.get("dependencies", []),
            )
            for p in data.get("packages", [])
        ]

        return cls(
            said=data.get("d", ""),
            governed_by=data.get("governed_by", ""),
            resolved_at=datetime.fromisoformat(data.get("resolved_at", "2000-01-01T00:00:00+00:00")),
            resolver=data.get("resolver", "unknown"),
            python_version=data.get("python", {}).get("version", ""),
            platform=data.get("python", {}).get("platform", ""),
            packages=packages,
        )


def compute_said(data: dict) -> str:
    """Compute SAID for data using KERI's Blake3."""
    # Remove existing SAID field for computation
    data_copy = {k: v for k, v in data.items() if k != "d"}

    # Deterministic serialization
    raw = json.dumps(data_copy, sort_keys=True, separators=(",", ":")).encode()

    # Use Blake3 via keri
    diger = coring.Diger(ser=raw, code=coring.MtrDex.Blake3_256)
    return diger.qb64


def get_resolver_version() -> str:
    """Get UV or pip version for lock file metadata."""
    try:
        result = subprocess.run(
            ["uv", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # "uv 0.5.0" -> "uv-0.5.0"
            return result.stdout.strip().replace(" ", "-")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            # "pip 24.0 from ..." -> "pip-24.0"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return f"{parts[0]}-{parts[1]}"
    except subprocess.TimeoutExpired:
        pass

    return "unknown"


def get_python_info(venv_path: Optional[Path] = None) -> Tuple[str, str]:
    """Get Python version and platform."""
    python = sys.executable
    if venv_path:
        venv_python = venv_path / "bin" / "python"
        if venv_python.exists():
            python = str(venv_python)

    try:
        result = subprocess.run(
            [python, "-c", "import sys, platform; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}|{platform.system().lower()}-{platform.machine()}')"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split("|")
            if len(parts) == 2:
                return parts[0], parts[1]
    except subprocess.TimeoutExpired:
        pass

    return "", ""


def get_installed_packages(venv_path: Optional[Path] = None) -> List[ResolvedPackage]:
    """Get list of installed packages with versions.

    Supports both pip-managed and UV-managed venvs.
    """
    packages = []

    # Try UV first (works for UV-managed venvs)
    if venv_path:
        try:
            result = subprocess.run(
                ["uv", "pip", "list", "--format=json", "--python", str(venv_path / "bin" / "python")],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for pkg in json.loads(result.stdout):
                    packages.append(ResolvedPackage(
                        name=pkg["name"],
                        version=pkg["version"],
                        source="pypi",
                    ))
                return packages
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

    # Fallback to pip
    python = sys.executable
    if venv_path:
        venv_python = venv_path / "bin" / "python"
        if venv_python.exists():
            python = str(venv_python)

    try:
        result = subprocess.run(
            [python, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            for pkg in json.loads(result.stdout):
                packages.append(ResolvedPackage(
                    name=pkg["name"],
                    version=pkg["version"],
                    source="pypi",
                ))
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return packages


def generate_lock_file(
    stack_said: str,
    venv_path: Optional[Path] = None,
    packages: Optional[List[ResolvedPackage]] = None,
) -> LockFile:
    """
    Generate a SAIDified lock file from installed packages.

    Args:
        stack_said: The governing stack SAID
        venv_path: Optional venv to inspect
        packages: Optional pre-resolved packages (if not provided, reads from venv)

    Returns:
        LockFile with computed SAID
    """
    if packages is None:
        packages = get_installed_packages(venv_path)

    python_version, platform = get_python_info(venv_path)
    resolver = get_resolver_version()

    # Create lock file without SAID first
    lock_data = {
        "v": "GS10JSON000000_",
        "governed_by": stack_said,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "resolver": resolver,
        "python": {
            "version": python_version,
            "platform": platform,
        },
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "source": p.source,
                "wheel_said": p.wheel_said,
            }
            for p in sorted(packages, key=lambda x: x.name.lower())
        ],
    }

    # Compute SAID
    said = compute_said(lock_data)

    return LockFile(
        said=said,
        governed_by=stack_said,
        resolved_at=datetime.now(timezone.utc),
        resolver=resolver,
        python_version=python_version,
        platform=platform,
        packages=packages,
    )


def save_lock_file(lock_file: LockFile, path: Path) -> None:
    """Save lock file to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(lock_file.to_json())


def load_lock_file(path: Path) -> Optional[LockFile]:
    """Load lock file from disk."""
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
        return LockFile.from_dict(data)
    except (json.JSONDecodeError, KeyError):
        return None


def verify_lock_file(lock_file: LockFile) -> Tuple[bool, str]:
    """
    Verify lock file SAID matches content.

    Returns:
        (verified, message)
    """
    # Recompute SAID from content
    data = lock_file.to_dict()
    expected_said = lock_file.said
    computed_said = compute_said(data)

    if computed_said == expected_said:
        return True, "Lock file SAID verified"
    else:
        return False, f"SAID mismatch: expected {expected_said}, computed {computed_said}"
