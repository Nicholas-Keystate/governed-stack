# -*- encoding: utf-8 -*-
"""
keri-sec Runtime Module - Cryptographic Dependency Management.

Provides GAID-based runtime environment verification:
- RuntimeManifest: Captures complete runtime configuration
- RuntimeGAID: Governed runtime with version chain
- RuntimeChecker: Verify environment against manifest
- RuntimeResolver: Resolve GAID to dependencies

This solves "dependency hell" cryptographically - if your manifest SAID
matches the expected SAID, you have exactly the same runtime configuration.

Usage:
    from keri_sec.runtime import (
        RuntimeManifest,
        capture_current_manifest,
        RuntimeGAIDRegistry,
        RuntimeChecker,
    )

    # Capture current environment
    manifest = capture_current_manifest()
    print(f"Runtime SAID: {manifest.said}")

    # Register as governed runtime
    registry = RuntimeGAIDRegistry()
    runtime = registry.register(
        name="production",
        manifest=manifest,
        governance_rules=GovernanceRules(
            min_keripy_version="1.2.0",
        ),
    )

    # Verify later
    result = registry.verify(runtime.gaid)
    if not result.compliant:
        print(f"Violations: {result.violations}")
"""

from .manifest import (
    RuntimeManifest,
    capture_current_manifest,
    load_manifest,
    save_manifest,
)

from .gaid import (
    RuntimeGAID,
    RuntimeGAIDRegistry,
    RuntimeStatus,
    RuntimeVersion,
    GovernanceRules,
    DeprecationNotice,
    VerificationResult,
    get_runtime_gaid_registry,
    reset_runtime_gaid_registry,
)

from .checker import (
    RuntimeChecker,
    CheckResult,
    CheckViolation,
    ViolationSeverity,
)

from .resolver import (
    RuntimeResolver,
    DependencyGraph,
    ResolvedDependency,
    AvailabilityResult,
)

__all__ = [
    # Manifest
    "RuntimeManifest",
    "capture_current_manifest",
    "load_manifest",
    "save_manifest",
    # GAID
    "RuntimeGAID",
    "RuntimeGAIDRegistry",
    "RuntimeStatus",
    "RuntimeVersion",
    "GovernanceRules",
    "DeprecationNotice",
    "VerificationResult",
    "get_runtime_gaid_registry",
    "reset_runtime_gaid_registry",
    # Checker
    "RuntimeChecker",
    "CheckResult",
    "CheckViolation",
    "ViolationSeverity",
    # Resolver
    "RuntimeResolver",
    "DependencyGraph",
    "ResolvedDependency",
    "AvailabilityResult",
]
