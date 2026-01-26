# -*- encoding: utf-8 -*-
"""
Constraint Handlers - Transit-inspired, KERI-aligned.

This module implements a handler-based type system for constraint verification,
inspired by Cognitect's Transit format. Each constraint type has a handler
that knows how to serialize (for SAID computation) and verify (against environment).

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

Key patterns from Transit:
1. Handler-based extensibility - add new types without modifying core
2. Ground types vs extensions - extensions compose on well-known base types
3. Self-describing tags - type encoded in the value itself
4. No opaque blobs - everything decomposes to verifiable primitives
"""

import json
import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from keri.core import coring


@dataclass
class VerificationResult:
    """
    Result of constraint verification.

    Immutable after creation. Contains all information needed
    to understand why verification passed or failed.
    """
    verified: bool
    constraint_said: str
    actual_value: str
    expected_spec: str
    message: str = ""
    handler_code: str = ""


class ConstraintHandler(ABC):
    """
    Abstract handler for constraint verification.

    Transit-inspired: Each constraint type has a handler that knows
    how to serialize (for SAID computation) and verify (against environment).

    Implementors must provide:
    - code: Single-char CESR-style derivation code
    - type_name: Human-readable type identifier
    - serialize: Deterministic byte serialization for SAID
    - verify: Check constraint against current environment
    """

    @property
    @abstractmethod
    def code(self) -> str:
        """
        Single-char CESR-style code for this constraint type.

        These codes are inspired by CESR derivation codes and Transit's
        self-describing tags. The code appears in encoded constraints:

            "P:>=3.12"   # Python version constraint
            "K:keri>=1.2.0"  # Package constraint
        """

    @property
    @abstractmethod
    def type_name(self) -> str:
        """Human-readable type name (e.g., 'python', 'package')."""

    @abstractmethod
    def serialize(self, name: str, spec: str) -> bytes:
        """
        Deterministic serialization for SAID computation.

        MUST be deterministic: same inputs = same bytes = same SAID.
        Uses sorted JSON by default for interoperability.

        Args:
            name: Constraint name (e.g., 'python', 'keri')
            spec: Version specification (e.g., '>=3.12', '>=1.2.0')

        Returns:
            Deterministic byte representation
        """

    @abstractmethod
    def verify(self, name: str, spec: str) -> VerificationResult:
        """
        Verify constraint against current environment.

        Args:
            name: Constraint name
            spec: Version specification to check against

        Returns:
            VerificationResult with pass/fail and details
        """

    def compute_said(self, name: str, spec: str) -> str:
        """
        Compute SAID for this constraint.

        Uses keripy's Diger with Blake3_256 for performance.
        """
        ser = self.serialize(name, spec)
        diger = coring.Diger(ser=ser, code=coring.MtrDex.Blake3_256)
        return diger.qb64


class PythonVersionHandler(ConstraintHandler):
    """Handler for Python runtime version constraints."""

    @property
    def code(self) -> str:
        return "P"

    @property
    def type_name(self) -> str:
        return "python"

    def serialize(self, name: str, spec: str) -> bytes:
        """Serialize Python version constraint."""
        data = {
            "handler": self.code,
            "type": self.type_name,
            "name": name,
            "spec": spec,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, name: str, spec: str) -> VerificationResult:
        """Check Python version against specification."""
        current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        satisfied = _version_satisfies(current, spec)

        return VerificationResult(
            verified=satisfied,
            constraint_said=self.compute_said(name, spec),
            actual_value=current,
            expected_spec=spec,
            message="" if satisfied else f"Python {current} does not satisfy {spec}",
            handler_code=self.code,
        )


class PackageHandler(ConstraintHandler):
    """Handler for Python package (pip/uv) constraints."""

    @property
    def code(self) -> str:
        return "K"  # 'K' for pacKage (P taken by Python)

    @property
    def type_name(self) -> str:
        return "package"

    def serialize(self, name: str, spec: str) -> bytes:
        """Serialize package constraint."""
        data = {
            "handler": self.code,
            "type": self.type_name,
            "name": name,
            "spec": spec,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, name: str, spec: str) -> VerificationResult:
        """Check if package is installed with correct version."""
        said = self.compute_said(name, spec)

        try:
            from importlib.metadata import PackageNotFoundError, version

            try:
                installed = version(name)
                satisfied = _version_satisfies(installed, spec)

                return VerificationResult(
                    verified=satisfied,
                    constraint_said=said,
                    actual_value=installed,
                    expected_spec=spec,
                    message="" if satisfied else f"{name}=={installed} does not satisfy {spec}",
                    handler_code=self.code,
                )
            except PackageNotFoundError:
                return VerificationResult(
                    verified=False,
                    constraint_said=said,
                    actual_value="",
                    expected_spec=spec,
                    message=f"Package {name} not installed",
                    handler_code=self.code,
                )
        except ImportError:
            return VerificationResult(
                verified=False,
                constraint_said=said,
                actual_value="",
                expected_spec=spec,
                message="Cannot check package versions (importlib.metadata unavailable)",
                handler_code=self.code,
            )


class SystemPackageHandler(ConstraintHandler):
    """Handler for system package (brew/apt) constraints."""

    @property
    def code(self) -> str:
        return "S"

    @property
    def type_name(self) -> str:
        return "system"

    def serialize(self, name: str, spec: str) -> bytes:
        """Serialize system package constraint."""
        data = {
            "handler": self.code,
            "type": self.type_name,
            "name": name,
            "spec": spec,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, name: str, spec: str) -> VerificationResult:
        """Check system package version."""
        said = self.compute_said(name, spec)

        if sys.platform == "darwin":
            # macOS: Use brew
            try:
                result = subprocess.run(
                    ["brew", "list", "--versions", name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split()
                    if len(parts) >= 2:
                        installed = parts[1]
                        satisfied = _version_satisfies(installed, spec)
                        return VerificationResult(
                            verified=satisfied,
                            constraint_said=said,
                            actual_value=installed,
                            expected_spec=spec,
                            message="" if satisfied else f"{name}=={installed} does not satisfy {spec}",
                            handler_code=self.code,
                        )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return VerificationResult(
            verified=False,
            constraint_said=said,
            actual_value="",
            expected_spec=spec,
            message=f"Cannot determine {name} version (brew not available or package not found)",
            handler_code=self.code,
        )


class BinaryHandler(ConstraintHandler):
    """Handler for binary tool (CLI) constraints."""

    @property
    def code(self) -> str:
        return "B"

    @property
    def type_name(self) -> str:
        return "binary"

    def serialize(self, name: str, spec: str) -> bytes:
        """Serialize binary constraint."""
        data = {
            "handler": self.code,
            "type": self.type_name,
            "name": name,
            "spec": spec,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def verify(self, name: str, spec: str) -> VerificationResult:
        """Check if binary is available with correct version."""
        said = self.compute_said(name, spec)

        binary_path = shutil.which(name)
        if not binary_path:
            return VerificationResult(
                verified=False,
                constraint_said=said,
                actual_value="",
                expected_spec=spec,
                message=f"Binary {name} not found in PATH",
                handler_code=self.code,
            )

        try:
            result = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Extract version from output
            match = re.search(r"(\d+\.\d+\.?\d*)", result.stdout + result.stderr)
            if match:
                installed = match.group(1)
                satisfied = _version_satisfies(installed, spec)
                return VerificationResult(
                    verified=satisfied,
                    constraint_said=said,
                    actual_value=installed,
                    expected_spec=spec,
                    message="" if satisfied else f"{name}=={installed} does not satisfy {spec}",
                    handler_code=self.code,
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return VerificationResult(
            verified=False,
            constraint_said=said,
            actual_value="unknown",
            expected_spec=spec,
            message=f"Cannot determine {name} version",
            handler_code=self.code,
        )


# =============================================================================
# Handler Registry (Transit-style)
# =============================================================================

# Ground handlers - built-in, well-known verification
HANDLERS: Dict[str, ConstraintHandler] = {
    "python": PythonVersionHandler(),
    "package": PackageHandler(),
    "system": SystemPackageHandler(),
    "binary": BinaryHandler(),
}

# Code-to-handler mapping for decoding
_CODE_TO_HANDLER: Dict[str, ConstraintHandler] = {
    "P": HANDLERS["python"],
    "K": HANDLERS["package"],
    "S": HANDLERS["system"],
    "B": HANDLERS["binary"],
}


def get_handler(constraint_type: str) -> ConstraintHandler:
    """
    Get handler for constraint type.

    Args:
        constraint_type: Type name (e.g., 'python', 'package') or code (e.g., 'P', 'K')

    Returns:
        ConstraintHandler for the type

    Raises:
        ValueError: If no handler is registered for the type
    """
    # Try by name first
    if constraint_type in HANDLERS:
        return HANDLERS[constraint_type]

    # Try by code
    if constraint_type in _CODE_TO_HANDLER:
        return _CODE_TO_HANDLER[constraint_type]

    raise ValueError(f"No handler registered for constraint type: {constraint_type}")


def register_handler(type_name: str, handler: ConstraintHandler) -> None:
    """
    Register a custom handler (Transit extension pattern).

    This allows adding new constraint types without modifying core code.
    The handler's code must not conflict with existing codes.

    Args:
        type_name: Human-readable type name
        handler: ConstraintHandler implementation

    Raises:
        ValueError: If code conflicts with existing handler
    """
    # Check for code conflict
    if handler.code in _CODE_TO_HANDLER and _CODE_TO_HANDLER[handler.code] != handler:
        existing = _CODE_TO_HANDLER[handler.code]
        raise ValueError(
            f"Handler code '{handler.code}' already used by {existing.type_name}"
        )

    HANDLERS[type_name] = handler
    _CODE_TO_HANDLER[handler.code] = handler


def list_handlers() -> List[Dict[str, str]]:
    """
    List all registered handlers.

    Returns:
        List of dicts with 'code', 'type_name' for each handler
    """
    return [
        {"code": h.code, "type_name": h.type_name}
        for h in HANDLERS.values()
    ]


# =============================================================================
# Version Comparison Utilities
# =============================================================================

def _version_satisfies(installed: str, spec: str) -> bool:
    """
    Check if installed version satisfies specification (PEP 440).

    Uses packaging library if available, falls back to simple comparison.
    """
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        return Version(installed) in SpecifierSet(spec)
    except Exception:
        # Fallback: simple comparison
        if spec.startswith(">="):
            return _compare_versions(installed, spec[2:]) >= 0
        elif spec.startswith("<="):
            return _compare_versions(installed, spec[2:]) <= 0
        elif spec.startswith(">"):
            return _compare_versions(installed, spec[1:]) > 0
        elif spec.startswith("<"):
            return _compare_versions(installed, spec[1:]) < 0
        elif spec.startswith("=="):
            return installed == spec[2:]
        return installed == spec


def _compare_versions(v1: str, v2: str) -> int:
    """Compare version strings. Returns -1, 0, or 1."""
    def normalize(v: str) -> List[int]:
        return [int(x) for x in re.sub(r"[^0-9.]", "", v).split(".") if x]

    n1, n2 = normalize(v1), normalize(v2)

    # Pad to same length
    while len(n1) < len(n2):
        n1.append(0)
    while len(n2) < len(n1):
        n2.append(0)

    for a, b in zip(n1, n2):
        if a != b:
            return -1 if a < b else 1
    return 0
