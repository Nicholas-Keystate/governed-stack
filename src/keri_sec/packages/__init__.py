# -*- encoding: utf-8 -*-
"""
Package DAID - Supply Chain Security for Python Packages.

Provides DAID governance for Python packages:
- Stable identifiers through version releases
- Publisher AID binding (self-sovereign identity)
- Content verification via SAIDs
- Supply chain attack mitigation

Usage:
    from keri_sec.packages import (
        PackageDAIDRegistry,
        get_package_daid_registry,
    )

    # Get singleton registry
    registry = get_package_daid_registry()

    # Register a package
    pkg = registry.register(
        name="mypackage",
        publisher_aid="EPUBLISHER...",
    )

    # Add version
    registry.add_version(
        daid=pkg.daid,
        version="1.0.0",
        source_said="ESOURCE...",
    )

    # Verify installed package
    result = registry.verify_package("mypackage", "1.0.0", actual_said)
"""

from keri_sec.packages.daid import (
    PackageDAID,
    PackageDAIDRegistry,
    PackageStatus,
    PackageVersion,
    DeprecationNotice,
    VerificationResult,
    get_package_daid_registry,
    reset_package_daid_registry,
)

__all__ = [
    "PackageDAID",
    "PackageDAIDRegistry",
    "PackageStatus",
    "PackageVersion",
    "DeprecationNotice",
    "VerificationResult",
    "get_package_daid_registry",
    "reset_package_daid_registry",
]
