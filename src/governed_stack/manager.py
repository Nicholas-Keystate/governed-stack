# -*- encoding: utf-8 -*-
"""
Stack Manager - KERI-Governed Dependency Management

HYPER-EXPERIMENTAL: API may change without notice.

Uses keripy's Diger for SAID computation following Samuel Smith's principles:
- Content-addressable design (SAIDs for everything)
- Deterministic serialization (sorted JSON)
- Blake3 for performance
- Controller AIDs for authorization

Handler system inspired by Cognitect's Transit format:
- Handler-based type extensibility
- Ground types vs extension types
- "No opaque blobs" decomposition principle

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

No asyncio. No callbacks. Pure functional where possible.
"""

import json
import logging
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from keri.core import coring

# Handler imports - Transit-inspired type system
from governed_stack.handlers import (
    ConstraintHandler,
    VerificationResult,
    get_handler,
    HANDLERS,
)

logger = logging.getLogger(__name__)


class ConstraintType(str, Enum):
    """
    Types of constraints that can be governed.

    Following KERI artifact taxonomy principles:
    - Clear enumeration of types
    - Each type has defined semantics
    """
    PYTHON = "python"        # Python runtime version
    PACKAGE = "package"      # Python package (pip/uv)
    SYSTEM = "system"        # System package (brew/apt)
    BINARY = "binary"        # Binary tool (kli, etc.)


@dataclass
class Constraint:
    """
    A single governed constraint.

    Immutable after creation. Changes create new versions.
    """
    name: str
    constraint_type: ConstraintType
    version_spec: str  # PEP 440 for Python packages
    said: str  # Content SAID of this constraint
    rationale: str = ""
    verified_versions: List[str] = field(default_factory=list)
    breaking_change_notice_days: int = 14


@dataclass
class ConstraintVersion:
    """A version in constraint history."""
    sequence: int
    said: str
    version_spec: str
    change_summary: str
    timestamp: str
    signer_aid: str


@dataclass
class StackProfile:
    """
    A collection of constraints forming a deployment stack.

    The stack SAID is derived from the sorted list of constraint SAIDs,
    ensuring deterministic identity regardless of definition order.
    """
    said: str  # Stack SAID (hash of sorted constraint SAIDs + controller)
    name: str
    constraints: Dict[str, Constraint]  # name -> Constraint
    controller_aid: str
    created_at: str
    updated_at: str


@dataclass
class ComplianceResult:
    """Result of checking environment compliance against a stack."""
    compliant: bool
    stack_said: str
    checks: Dict[str, "ConstraintCheck"]
    missing: List[str]
    outdated: List[str]
    timestamp: str


@dataclass
class ConstraintCheck:
    """Result of checking a single constraint."""
    name: str
    required: str
    installed: Optional[str]
    compliant: bool
    error: Optional[str] = None


def compute_said(data: Any) -> str:
    """
    Compute SAID using keripy's Diger.

    Uses Blake3_256 for performance per Sam Smith's recommendations.
    Data is JSON-serialized with sorted keys for determinism.
    """
    if isinstance(data, str):
        ser = data.encode("utf-8")
    elif isinstance(data, bytes):
        ser = data
    else:
        ser = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    diger = coring.Diger(ser=ser, code=coring.MtrDex.Blake3_256)
    return diger.qb64


class StackManager:
    """
    KERI-governed dependency management.

    Key principles (following Samuel Smith's guidance):
    1. SAIDs for content-addressability
    2. Controller AIDs for authorization (who can modify)
    3. Append-only history (no deletion, only supersession)
    4. Deterministic serialization (reproducible SAIDs)

    Thread-safe via mutex. No asyncio - keeps it simple.
    """

    def __init__(
        self,
        base_path: Optional[Path] = None,
        uv_path: Optional[Path] = None,
    ):
        """
        Initialize stack manager.

        Args:
            base_path: Path for storing stack definitions (default: ~/.governed-stack/)
            uv_path: Path to UV binary (auto-detected if not provided)
        """
        self.base_path = base_path or Path.home() / ".governed-stack"
        self.uv_path = uv_path or self._find_uv()

        # Ensure directories exist
        self.stacks_path = self.base_path / "stacks"
        self.history_path = self.base_path / "history"
        self.stacks_path.mkdir(parents=True, exist_ok=True)
        self.history_path.mkdir(parents=True, exist_ok=True)

        # In-memory cache
        self._stacks: Dict[str, StackProfile] = {}
        self._constraint_history: Dict[str, List[ConstraintVersion]] = {}
        self._lock = threading.Lock()

        # Load existing stacks
        self._load_stacks()

    def _find_uv(self) -> Optional[Path]:
        """Find UV binary in PATH."""
        uv = shutil.which("uv")
        return Path(uv) if uv else None

    def _find_pip(self) -> Optional[Path]:
        """Find pip in current environment."""
        venv_pip = Path(sys.prefix) / "bin" / "pip"
        if venv_pip.exists():
            return venv_pip
        pip = shutil.which("pip")
        return Path(pip) if pip else None

    def _load_stacks(self) -> None:
        """Load existing stack definitions from disk."""
        for stack_file in self.stacks_path.glob("*.json"):
            try:
                data = json.loads(stack_file.read_text())
                constraints = {
                    name: Constraint(**c) for name, c in data["constraints"].items()
                }
                stack = StackProfile(
                    said=data["said"],
                    name=data["name"],
                    constraints=constraints,
                    controller_aid=data["controller_aid"],
                    created_at=data["created_at"],
                    updated_at=data["updated_at"],
                )
                self._stacks[stack.said] = stack
            except Exception as e:
                logger.warning(f"Failed to load stack {stack_file}: {e}")

    def _save_stack(self, stack: StackProfile) -> None:
        """Persist stack to disk."""
        data = {
            "said": stack.said,
            "name": stack.name,
            "constraints": {
                name: {
                    "name": c.name,
                    "constraint_type": c.constraint_type.value,
                    "version_spec": c.version_spec,
                    "said": c.said,
                    "rationale": c.rationale,
                    "verified_versions": c.verified_versions,
                    "breaking_change_notice_days": c.breaking_change_notice_days,
                }
                for name, c in stack.constraints.items()
            },
            "controller_aid": stack.controller_aid,
            "created_at": stack.created_at,
            "updated_at": stack.updated_at,
        }
        # Use SAID prefix for filename (safe characters)
        safe_said = stack.said.replace("/", "_").replace("+", "-")
        stack_file = self.stacks_path / f"{safe_said[:20]}.json"
        stack_file.write_text(json.dumps(data, indent=2))

    def define_stack(
        self,
        name: str,
        controller_aid: str,
        constraints: Dict[str, str],
        rationale: str = "",
        breaking_change_notice_days: int = 14,
    ) -> StackProfile:
        """
        Define a governed deployment stack.

        Each constraint gets a SAID. The stack SAID is derived from
        the sorted constraint SAIDs + controller AID for determinism.

        Args:
            name: Stack name (e.g., "keri-production")
            controller_aid: AID that controls this stack
            constraints: Dict of name -> version_spec
            rationale: Why these constraints
            breaking_change_notice_days: Notice period for breaking changes

        Returns:
            StackProfile with all constraint SAIDs
        """
        with self._lock:
            stack_constraints: Dict[str, Constraint] = {}
            constraint_saids = []

            for pkg_name, version_spec in constraints.items():
                # Determine constraint type
                if pkg_name == "python":
                    ctype = ConstraintType.PYTHON
                elif pkg_name.startswith("system:"):
                    ctype = ConstraintType.SYSTEM
                    pkg_name = pkg_name.replace("system:", "")
                elif pkg_name.startswith("binary:"):
                    ctype = ConstraintType.BINARY
                    pkg_name = pkg_name.replace("binary:", "")
                else:
                    ctype = ConstraintType.PACKAGE

                # Compute constraint SAID from content
                constraint_data = {
                    "name": pkg_name,
                    "type": ctype.value,
                    "spec": version_spec,
                    "stack": name,
                }
                constraint_said = compute_said(constraint_data)
                constraint_saids.append(constraint_said)

                stack_constraints[pkg_name] = Constraint(
                    name=pkg_name,
                    constraint_type=ctype,
                    version_spec=version_spec,
                    said=constraint_said,
                    rationale=rationale,
                    breaking_change_notice_days=breaking_change_notice_days,
                )

            # Compute stack SAID from sorted constraint SAIDs + controller
            # Sorting ensures deterministic SAID regardless of input order
            stack_data = {
                "name": name,
                "constraints": sorted(constraint_saids),
                "controller": controller_aid,
            }
            stack_said = compute_said(stack_data)

            now = datetime.now(timezone.utc).isoformat()
            stack = StackProfile(
                said=stack_said,
                name=name,
                constraints=stack_constraints,
                controller_aid=controller_aid,
                created_at=now,
                updated_at=now,
            )

            self._stacks[stack_said] = stack
            self._save_stack(stack)

            logger.info(f"Defined stack '{name}' SAID={stack_said[:20]}...")
            return stack

    def get_stack(self, stack_said: str) -> Optional[StackProfile]:
        """Get stack by SAID."""
        return self._stacks.get(stack_said)

    def get_stack_by_name(self, name: str) -> Optional[StackProfile]:
        """Get stack by name (returns most recent if multiple)."""
        for stack in sorted(
            self._stacks.values(),
            key=lambda s: s.updated_at,
            reverse=True
        ):
            if stack.name == name:
                return stack
        return None

    def list_stacks(self) -> List[StackProfile]:
        """List all defined stacks."""
        return list(self._stacks.values())

    def verify_stack(
        self,
        expected_said: str,
        name: str,
        controller_aid: str,
        constraints: Dict[str, str],
    ) -> Tuple[bool, str]:
        """
        Verify that constraints produce the expected SAID.

        This is the core tamper-detection mechanism. Given constraints,
        recompute the SAID and compare to expected. If they differ,
        the content has been modified.

        Args:
            expected_said: The SAID to verify against
            name: Stack name
            controller_aid: Controller AID
            constraints: Dict of name -> version_spec

        Returns:
            (verified: bool, computed_said: str)
        """
        # Recompute SAIDs using same algorithm as define_stack
        constraint_saids = []
        for pkg_name, version_spec in constraints.items():
            # Determine constraint type
            if pkg_name == "python":
                ctype = ConstraintType.PYTHON
            elif pkg_name.startswith("system:"):
                ctype = ConstraintType.SYSTEM
                pkg_name = pkg_name.replace("system:", "")
            elif pkg_name.startswith("binary:"):
                ctype = ConstraintType.BINARY
                pkg_name = pkg_name.replace("binary:", "")
            else:
                ctype = ConstraintType.PACKAGE

            constraint_data = {
                "name": pkg_name,
                "type": ctype.value,
                "spec": version_spec,
                "stack": name,
            }
            constraint_said = compute_said(constraint_data)
            constraint_saids.append(constraint_said)

        # Compute stack SAID
        stack_data = {
            "name": name,
            "constraints": sorted(constraint_saids),
            "controller": controller_aid,
        }
        computed_said = compute_said(stack_data)

        return (computed_said == expected_said, computed_said)

    def verify_pyproject(
        self,
        content: str,
        expected_said: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, str]]:
        """
        Verify a pyproject.toml matches its embedded SAID.

        Parses the pyproject.toml, extracts constraints, recomputes SAID,
        and verifies it matches the embedded SAID comment.

        Args:
            content: pyproject.toml content
            expected_said: Optional SAID to verify against (uses embedded if not provided)

        Returns:
            (verified: bool, said: Optional[str], extracted_constraints: dict)
        """
        extracted = {}
        embedded_said = None
        stack_name = None
        controller = None

        for line in content.split("\n"):
            # Extract SAID from header comment
            if "# SAID:" in line and embedded_said is None:
                embedded_said = line.split("# SAID:")[1].strip()

            # Extract stack name
            if "# Stack:" in line:
                stack_name = line.split("# Stack:")[1].strip()

            # Extract controller
            if "# Controller:" in line:
                controller = line.split("# Controller:")[1].strip()

            # Extract Python version
            if "requires-python" in line:
                match = re.search(r'requires-python\s*=\s*"([^"]+)"', line)
                if match:
                    extracted["python"] = match.group(1)

            # Extract dependencies
            if line.strip().startswith('"') and ">=" in line or "==" in line or "<=" in line:
                # Parse: "keri>=1.2.0",  # SAID: ...
                match = re.search(r'"([^"]+)"', line)
                if match:
                    dep = match.group(1)
                    # Split on first comparison operator
                    for op in [">=", "<=", "==", ">", "<", "~="]:
                        if op in dep:
                            name, version = dep.split(op, 1)
                            extracted[name] = f"{op}{version}"
                            break

        if not embedded_said and not expected_said:
            return (False, None, extracted)

        said_to_check = expected_said or embedded_said

        if not stack_name or not controller:
            return (False, said_to_check, extracted)

        verified, computed = self.verify_stack(
            expected_said=said_to_check,
            name=stack_name,
            controller_aid=controller,
            constraints=extracted,
        )

        return (verified, computed, extracted)

    def verify_requirements(
        self,
        content: str,
        expected_said: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Dict[str, str]]:
        """
        Verify a requirements.txt matches its embedded SAID.

        Args:
            content: requirements.txt content
            expected_said: Optional SAID to verify against

        Returns:
            (verified: bool, said: Optional[str], extracted_constraints: dict)
        """
        extracted = {}
        embedded_said = None
        stack_name = None
        controller = None

        for line in content.split("\n"):
            line = line.strip()

            # Extract header comments
            if line.startswith("#"):
                if "SAID:" in line and embedded_said is None:
                    embedded_said = line.split("SAID:")[1].strip()
                elif "Stack:" in line:
                    stack_name = line.split("Stack:")[1].strip()
                elif "Controller:" in line:
                    controller = line.split("Controller:")[1].strip()
                continue

            # Parse requirements
            if not line or line.startswith("-"):
                continue

            # Remove inline comments
            if "#" in line:
                line = line.split("#")[0].strip()

            # Parse: package>=version
            for op in [">=", "<=", "==", ">", "<", "~="]:
                if op in line:
                    name, version = line.split(op, 1)
                    extracted[name.strip()] = f"{op}{version.strip()}"
                    break

        if not embedded_said and not expected_said:
            return (False, None, extracted)

        said_to_check = expected_said or embedded_said

        if not stack_name or not controller:
            return (False, said_to_check, extracted)

        # Requirements.txt doesn't include python version
        # So we can't fully verify without it
        return (False, said_to_check, extracted)

    def update_constraint(
        self,
        stack_said: str,
        constraint_name: str,
        new_version_spec: str,
        change_summary: str,
        signer_aid: str,
    ) -> Optional[StackProfile]:
        """
        Update a constraint in a stack.

        Creates a NEW stack with updated constraint.
        Old stack remains for audit trail (append-only principle).

        Args:
            stack_said: Current stack SAID
            constraint_name: Constraint to update
            new_version_spec: New version specification
            change_summary: Description of change
            signer_aid: AID signing this change (must match controller)

        Returns:
            New StackProfile with updated constraint, or None if unauthorized
        """
        with self._lock:
            stack = self._stacks.get(stack_said)
            if not stack:
                logger.error(f"Stack {stack_said} not found")
                return None

            if signer_aid != stack.controller_aid:
                logger.error(f"Signer {signer_aid} != controller {stack.controller_aid}")
                return None

            if constraint_name not in stack.constraints:
                logger.error(f"Constraint {constraint_name} not in stack")
                return None

            # Build new constraints dict
            new_constraints = {}
            for name, spec in stack.constraints.items():
                if name == constraint_name:
                    new_constraints[name] = new_version_spec
                else:
                    new_constraints[name] = spec.version_spec

            # Record history
            old_constraint = stack.constraints[constraint_name]
            history_key = f"{stack.name}:{constraint_name}"
            if history_key not in self._constraint_history:
                self._constraint_history[history_key] = []

            self._constraint_history[history_key].append(ConstraintVersion(
                sequence=len(self._constraint_history[history_key]),
                said=old_constraint.said,
                version_spec=old_constraint.version_spec,
                change_summary=change_summary,
                timestamp=datetime.now(timezone.utc).isoformat(),
                signer_aid=signer_aid,
            ))

            # Create new stack
            return self.define_stack(
                name=stack.name,
                controller_aid=stack.controller_aid,
                constraints=new_constraints,
                rationale=f"Updated {constraint_name}: {change_summary}",
            )

    def check_compliance(
        self,
        stack_said: str,
        use_handlers: bool = True,
    ) -> ComplianceResult:
        """
        Check if current environment complies with stack constraints.

        Args:
            stack_said: Stack SAID to check against
            use_handlers: Use Transit-inspired handler system (default: True)

        Returns:
            ComplianceResult with detailed check info
        """
        stack = self._stacks.get(stack_said)
        if not stack:
            return ComplianceResult(
                compliant=False,
                stack_said=stack_said,
                checks={},
                missing=["Stack not found"],
                outdated=[],
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        checks: Dict[str, ConstraintCheck] = {}
        missing: List[str] = []
        outdated: List[str] = []

        for name, constraint in stack.constraints.items():
            if use_handlers:
                # Transit-inspired: delegate to type handlers
                check = self._check_with_handler(constraint)
            else:
                # Legacy path (kept for backward compatibility)
                if constraint.constraint_type == ConstraintType.PYTHON:
                    check = self._check_python(constraint)
                elif constraint.constraint_type == ConstraintType.PACKAGE:
                    check = self._check_package(constraint)
                elif constraint.constraint_type == ConstraintType.SYSTEM:
                    check = self._check_system(constraint)
                elif constraint.constraint_type == ConstraintType.BINARY:
                    check = self._check_binary(constraint)
                else:
                    check = ConstraintCheck(
                        name=name,
                        required=constraint.version_spec,
                        installed=None,
                        compliant=False,
                        error=f"Unknown type: {constraint.constraint_type}",
                    )

            checks[name] = check

            if check.installed is None:
                missing.append(name)
            elif not check.compliant:
                outdated.append(name)

        return ComplianceResult(
            compliant=len(missing) == 0 and len(outdated) == 0,
            stack_said=stack_said,
            checks=checks,
            missing=missing,
            outdated=outdated,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _check_with_handler(self, constraint: Constraint) -> ConstraintCheck:
        """
        Check constraint using Transit-inspired handler system.

        Delegates to the appropriate handler based on constraint type.
        Handlers are registered globally and can be extended.

        Args:
            constraint: Constraint to verify

        Returns:
            ConstraintCheck result
        """
        try:
            handler = get_handler(constraint.constraint_type.value)
            result = handler.verify(constraint.name, constraint.version_spec)

            return ConstraintCheck(
                name=constraint.name,
                required=constraint.version_spec,
                installed=result.actual_value if result.actual_value else None,
                compliant=result.verified,
                error=result.message if not result.verified else None,
            )
        except ValueError as e:
            # No handler registered for this type
            return ConstraintCheck(
                name=constraint.name,
                required=constraint.version_spec,
                installed=None,
                compliant=False,
                error=f"No handler for type: {constraint.constraint_type}",
            )

    def _check_python(self, constraint: Constraint) -> ConstraintCheck:
        """Check Python version."""
        current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        return ConstraintCheck(
            name="python",
            required=constraint.version_spec,
            installed=current,
            compliant=self._version_satisfies(current, constraint.version_spec),
        )

    def _check_package(self, constraint: Constraint) -> ConstraintCheck:
        """Check Python package version."""
        try:
            from importlib.metadata import version, PackageNotFoundError
            try:
                installed = version(constraint.name)
                return ConstraintCheck(
                    name=constraint.name,
                    required=constraint.version_spec,
                    installed=installed,
                    compliant=self._version_satisfies(installed, constraint.version_spec),
                )
            except PackageNotFoundError:
                return ConstraintCheck(
                    name=constraint.name,
                    required=constraint.version_spec,
                    installed=None,
                    compliant=False,
                    error="Not installed",
                )
        except ImportError:
            return ConstraintCheck(
                name=constraint.name,
                required=constraint.version_spec,
                installed=None,
                compliant=False,
                error="Cannot check",
            )

    def _check_system(self, constraint: Constraint) -> ConstraintCheck:
        """Check system package (brew/apt)."""
        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    ["brew", "list", "--versions", constraint.name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split()
                    if len(parts) >= 2:
                        installed = parts[1]
                        return ConstraintCheck(
                            name=constraint.name,
                            required=constraint.version_spec,
                            installed=installed,
                            compliant=self._version_satisfies(installed, constraint.version_spec),
                        )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return ConstraintCheck(
            name=constraint.name,
            required=constraint.version_spec,
            installed=None,
            compliant=False,
            error="Cannot determine",
        )

    def _check_binary(self, constraint: Constraint) -> ConstraintCheck:
        """Check binary tool version."""
        binary = shutil.which(constraint.name)
        if not binary:
            return ConstraintCheck(
                name=constraint.name,
                required=constraint.version_spec,
                installed=None,
                compliant=False,
                error="Not in PATH",
            )

        try:
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            match = re.search(r"(\d+\.\d+\.?\d*)", result.stdout + result.stderr)
            if match:
                installed = match.group(1)
                return ConstraintCheck(
                    name=constraint.name,
                    required=constraint.version_spec,
                    installed=installed,
                    compliant=self._version_satisfies(installed, constraint.version_spec),
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return ConstraintCheck(
            name=constraint.name,
            required=constraint.version_spec,
            installed="unknown",
            compliant=False,
            error="Cannot determine version",
        )

    def _version_satisfies(self, installed: str, spec: str) -> bool:
        """Check if installed version satisfies spec (PEP 440)."""
        try:
            from packaging.specifiers import SpecifierSet
            from packaging.version import Version
            return Version(installed) in SpecifierSet(spec)
        except Exception:
            # Fallback: simple comparison
            if spec.startswith(">="):
                return self._compare(installed, spec[2:]) >= 0
            elif spec.startswith("<="):
                return self._compare(installed, spec[2:]) <= 0
            elif spec.startswith(">"):
                return self._compare(installed, spec[1:]) > 0
            elif spec.startswith("<"):
                return self._compare(installed, spec[1:]) < 0
            elif spec.startswith("=="):
                return installed == spec[2:]
            return installed == spec

    def _compare(self, v1: str, v2: str) -> int:
        """Compare version strings."""
        def normalize(v):
            return [int(x) for x in re.sub(r"[^0-9.]", "", v).split(".") if x]

        n1, n2 = normalize(v1), normalize(v2)
        while len(n1) < len(n2):
            n1.append(0)
        while len(n2) < len(n1):
            n2.append(0)

        for a, b in zip(n1, n2):
            if a != b:
                return -1 if a < b else 1
        return 0

    def generate_pyproject(self, stack_said: str) -> str:
        """Generate pyproject.toml section from stack."""
        stack = self._stacks.get(stack_said)
        if not stack:
            return f"# Stack {stack_said} not found"

        lines = [
            f"# GOVERNED STACK - Do not edit manually",
            f"# Stack: {stack.name}",
            f"# SAID: {stack_said}",
            f"# Controller: {stack.controller_aid}",
            f"# Generated: {datetime.now(timezone.utc).isoformat()}",
            "",
            "[project]",
        ]

        python = stack.constraints.get("python")
        if python:
            lines.append(f'requires-python = "{python.version_spec}"')
            lines.append(f"# Constraint SAID: {python.said}")

        deps = []
        for name, c in sorted(stack.constraints.items()):
            if c.constraint_type == ConstraintType.PACKAGE:
                deps.append(f'    "{name}{c.version_spec}",  # SAID: {c.said}')

        if deps:
            lines.append("")
            lines.append("dependencies = [")
            lines.extend(deps)
            lines.append("]")

        return "\n".join(lines)

    def generate_requirements(self, stack_said: str) -> str:
        """Generate requirements.txt from stack."""
        stack = self._stacks.get(stack_said)
        if not stack:
            return f"# Stack {stack_said} not found"

        lines = [
            f"# GOVERNED STACK - Do not edit manually",
            f"# Stack: {stack.name}",
            f"# SAID: {stack_said}",
            f"# Controller: {stack.controller_aid}",
            "",
        ]

        for name, c in sorted(stack.constraints.items()):
            if c.constraint_type == ConstraintType.PACKAGE:
                lines.append(f"{name}{c.version_spec}  # SAID: {c.said}")

        return "\n".join(lines)

    def install_with_uv(
        self,
        stack_said: str,
        upgrade: bool = False,
        venv_path: Optional[Path] = None,
    ) -> Tuple[bool, str]:
        """
        Install stack dependencies using UV.

        Args:
            stack_said: Stack SAID to install
            upgrade: Upgrade existing packages
            venv_path: If provided, create venv and install there
        """
        if not self.uv_path:
            return False, "UV not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh"

        stack = self._stacks.get(stack_said)
        if not stack:
            return False, f"Stack {stack_said} not found"

        output_lines = []

        # Create venv if requested
        if venv_path:
            venv_path = Path(venv_path)

            # Get Python version from stack
            python_constraint = stack.constraints.get("python")
            python_version = None
            if python_constraint:
                # Extract version from constraint like ">=3.12"
                import re
                match = re.search(r"(\d+\.\d+)", python_constraint.version_spec)
                if match:
                    python_version = match.group(1)

            # Create venv with UV
            venv_cmd = [str(self.uv_path), "venv", str(venv_path)]
            if python_version:
                venv_cmd.extend(["--python", python_version])

            try:
                result = subprocess.run(venv_cmd, capture_output=True, text=True, timeout=60)
                if result.returncode != 0:
                    return False, f"Failed to create venv: {result.stderr}"
                output_lines.append(f"Created venv at {venv_path}")
                if python_version:
                    output_lines.append(f"Python version: {python_version}")
            except Exception as e:
                return False, f"venv creation error: {e}"

        packages = [
            f"{c.name}{c.version_spec}"
            for c in stack.constraints.values()
            if c.constraint_type == ConstraintType.PACKAGE
        ]

        if not packages:
            return True, "\n".join(output_lines + ["No packages to install"])

        # Build install command
        cmd = [str(self.uv_path), "pip", "install"]
        if upgrade:
            cmd.append("--upgrade")

        # If venv was created, target it
        if venv_path:
            cmd.extend(["--python", str(venv_path / "bin" / "python")])

        cmd.extend(packages)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output_lines.append(result.stdout + result.stderr)
            success = result.returncode == 0
            if success and venv_path:
                output_lines.append(f"\nActivate with: source {venv_path}/bin/activate")
            return success, "\n".join(output_lines)
        except subprocess.TimeoutExpired:
            return False, "Timeout after 5 minutes"
        except Exception as e:
            return False, str(e)

    def install_with_pip(
        self,
        stack_said: str,
        upgrade: bool = False,
    ) -> Tuple[bool, str]:
        """Install stack dependencies using pip (fallback)."""
        pip_path = self._find_pip()
        if not pip_path:
            return False, "pip not found"

        stack = self._stacks.get(stack_said)
        if not stack:
            return False, f"Stack {stack_said} not found"

        packages = [
            f"{c.name}{c.version_spec}"
            for c in stack.constraints.values()
            if c.constraint_type == ConstraintType.PACKAGE
        ]

        if not packages:
            return True, "No packages to install"

        cmd = [str(pip_path), "install"]
        if upgrade:
            cmd.append("--upgrade")
        cmd.extend(packages)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)


# Singleton management
_stack_manager: Optional[StackManager] = None
_lock = threading.Lock()


def get_stack_manager(base_path: Optional[Path] = None) -> StackManager:
    """Get or create singleton StackManager."""
    global _stack_manager
    with _lock:
        if _stack_manager is None:
            _stack_manager = StackManager(base_path=base_path)
        return _stack_manager


def reset_stack_manager() -> None:
    """Reset singleton (for testing)."""
    global _stack_manager
    with _lock:
        _stack_manager = None
