# -*- encoding: utf-8 -*-
"""
RuntimeChecker - Verify current environment against RuntimeManifest.

Provides detailed checking of runtime environment against a stored manifest,
with specific violation reporting for each component.

Usage:
    from keri_sec.runtime import RuntimeChecker, load_manifest

    checker = RuntimeChecker()
    expected = load_manifest("expected_runtime.json")
    result = checker.check(expected)

    if not result.passed:
        for violation in result.violations:
            print(f"  {violation.component}: {violation.message}")
"""

import importlib.metadata
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .manifest import RuntimeManifest, capture_current_manifest


class ViolationSeverity(Enum):
    """Severity of a check violation."""
    ERROR = "error"      # Must fix - environment is non-compliant
    WARNING = "warning"  # Should fix - may cause issues
    INFO = "info"        # Advisory - environment differs but acceptable


@dataclass
class CheckViolation:
    """A single check violation."""
    component: str
    severity: ViolationSeverity
    message: str
    expected: Any = None
    actual: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component": self.component,
            "severity": self.severity.value,
            "message": self.message,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass
class CheckResult:
    """Result of runtime check."""
    passed: bool
    expected_said: str
    actual_said: str
    violations: List[CheckViolation] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def error_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == ViolationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == ViolationSeverity.WARNING)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "expected_said": self.expected_said,
            "actual_said": self.actual_said,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "violations": [v.to_dict() for v in self.violations],
            "checked_at": self.checked_at,
        }


class RuntimeChecker:
    """
    Verifies current runtime environment against expected manifest.

    Performs detailed component-by-component checking with specific
    violation reporting.
    """

    def __init__(
        self,
        algorithm_registry=None,
        strict_platform: bool = False,
        strict_algorithms: bool = True,
    ):
        """
        Initialize checker.

        Args:
            algorithm_registry: Optional AlgorithmDAIDRegistry for algorithm lookups
            strict_platform: If True, platform differences are errors (default: warnings)
            strict_algorithms: If True, algorithm mismatches are errors (default: True)
        """
        self._algorithm_registry = algorithm_registry
        self._strict_platform = strict_platform
        self._strict_algorithms = strict_algorithms

    def check(
        self,
        expected: RuntimeManifest,
        actual: Optional[RuntimeManifest] = None,
    ) -> CheckResult:
        """
        Check current environment against expected manifest.

        Args:
            expected: Expected RuntimeManifest
            actual: Optional actual manifest (captures current if None)

        Returns:
            CheckResult with pass/fail and violations
        """
        if actual is None:
            actual = capture_current_manifest(algorithm_registry=self._algorithm_registry)

        violations: List[CheckViolation] = []

        # Check Python version
        if expected.python_version != actual.python_version:
            # Only error if major.minor differs
            expected_parts = expected.python_version.split('.')[:2]
            actual_parts = actual.python_version.split('.')[:2]
            if expected_parts != actual_parts:
                violations.append(CheckViolation(
                    component="python_version",
                    severity=ViolationSeverity.ERROR,
                    message=f"Python version mismatch",
                    expected=expected.python_version,
                    actual=actual.python_version,
                ))
            else:
                violations.append(CheckViolation(
                    component="python_version",
                    severity=ViolationSeverity.INFO,
                    message=f"Python patch version differs",
                    expected=expected.python_version,
                    actual=actual.python_version,
                ))

        # Check keripy version
        if expected.keripy_version != actual.keripy_version:
            violations.append(CheckViolation(
                component="keripy_version",
                severity=ViolationSeverity.ERROR,
                message=f"keripy version mismatch",
                expected=expected.keripy_version,
                actual=actual.keripy_version,
            ))

        # Check keripy SAID
        if expected.keripy_said != actual.keripy_said:
            violations.append(CheckViolation(
                component="keripy_said",
                severity=ViolationSeverity.ERROR,
                message=f"keripy package SAID mismatch (different installation)",
                expected=expected.keripy_said,
                actual=actual.keripy_said,
            ))

        # Check hio version
        if expected.hio_version != actual.hio_version:
            violations.append(CheckViolation(
                component="hio_version",
                severity=ViolationSeverity.WARNING,
                message=f"hio version mismatch",
                expected=expected.hio_version,
                actual=actual.hio_version,
            ))

        # Check algorithm GAIDs
        self._check_algorithms(expected, actual, violations)

        # Check protocol GAIDs
        self._check_protocols(expected, actual, violations)

        # Check platform (if strict)
        self._check_platform(expected, actual, violations)

        # Determine pass/fail
        has_errors = any(v.severity == ViolationSeverity.ERROR for v in violations)

        return CheckResult(
            passed=not has_errors,
            expected_said=expected.said,
            actual_said=actual.said,
            violations=violations,
        )

    def _check_algorithms(
        self,
        expected: RuntimeManifest,
        actual: RuntimeManifest,
        violations: List[CheckViolation],
    ) -> None:
        """Check algorithm GAIDs."""
        severity = ViolationSeverity.ERROR if self._strict_algorithms else ViolationSeverity.WARNING

        # Check for missing algorithms
        for algo, gaid in expected.algorithm_gaids.items():
            if algo not in actual.algorithm_gaids:
                violations.append(CheckViolation(
                    component=f"algorithm:{algo}",
                    severity=severity,
                    message=f"Algorithm missing: {algo}",
                    expected=gaid,
                    actual=None,
                ))
            elif actual.algorithm_gaids[algo] != gaid:
                violations.append(CheckViolation(
                    component=f"algorithm:{algo}",
                    severity=severity,
                    message=f"Algorithm GAID mismatch: {algo}",
                    expected=gaid,
                    actual=actual.algorithm_gaids[algo],
                ))

        # Check for unexpected algorithms
        for algo in actual.algorithm_gaids:
            if algo not in expected.algorithm_gaids:
                violations.append(CheckViolation(
                    component=f"algorithm:{algo}",
                    severity=ViolationSeverity.INFO,
                    message=f"Unexpected algorithm present: {algo}",
                    expected=None,
                    actual=actual.algorithm_gaids[algo],
                ))

    def _check_protocols(
        self,
        expected: RuntimeManifest,
        actual: RuntimeManifest,
        violations: List[CheckViolation],
    ) -> None:
        """Check protocol GAIDs."""
        for protocol, gaid in expected.protocol_gaids.items():
            if protocol not in actual.protocol_gaids:
                violations.append(CheckViolation(
                    component=f"protocol:{protocol}",
                    severity=ViolationSeverity.WARNING,
                    message=f"Protocol GAID missing: {protocol}",
                    expected=gaid,
                    actual=None,
                ))
            elif actual.protocol_gaids[protocol] != gaid:
                violations.append(CheckViolation(
                    component=f"protocol:{protocol}",
                    severity=ViolationSeverity.WARNING,
                    message=f"Protocol GAID mismatch: {protocol}",
                    expected=gaid,
                    actual=actual.protocol_gaids[protocol],
                ))

    def _check_platform(
        self,
        expected: RuntimeManifest,
        actual: RuntimeManifest,
        violations: List[CheckViolation],
    ) -> None:
        """Check platform info."""
        severity = ViolationSeverity.ERROR if self._strict_platform else ViolationSeverity.INFO

        expected_system = expected.platform_info.get("system", "")
        actual_system = actual.platform_info.get("system", "")

        if expected_system and expected_system != actual_system:
            violations.append(CheckViolation(
                component="platform:system",
                severity=severity,
                message=f"Platform system differs",
                expected=expected_system,
                actual=actual_system,
            ))

        expected_arch = expected.platform_info.get("machine", "")
        actual_arch = actual.platform_info.get("machine", "")

        if expected_arch and expected_arch != actual_arch:
            violations.append(CheckViolation(
                component="platform:machine",
                severity=severity,
                message=f"Platform architecture differs",
                expected=expected_arch,
                actual=actual_arch,
            ))

    def check_said_only(self, expected_said: str) -> CheckResult:
        """
        Quick check - just compare SAIDs.

        This is the fastest check but provides no detail on what differs.

        Args:
            expected_said: Expected manifest SAID

        Returns:
            CheckResult with pass/fail
        """
        actual = capture_current_manifest(algorithm_registry=self._algorithm_registry)

        if actual.said == expected_said:
            return CheckResult(
                passed=True,
                expected_said=expected_said,
                actual_said=actual.said,
            )
        else:
            return CheckResult(
                passed=False,
                expected_said=expected_said,
                actual_said=actual.said,
                violations=[CheckViolation(
                    component="manifest",
                    severity=ViolationSeverity.ERROR,
                    message="Manifest SAID mismatch",
                    expected=expected_said,
                    actual=actual.said,
                )],
            )
