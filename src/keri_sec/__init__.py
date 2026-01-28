# -*- encoding: utf-8 -*-
"""
keri-sec - KERI-Governed Dependency Management

HYPER-EXPERIMENTAL: This package is in early development.
API may change without notice. Use at your own risk.

Provides cryptographic source of truth for version constraints using KERI primitives.
Bridges governance with execution (UV, pip) without compromising security.

Inspired by Cognitect's Transit format for handler-based type extensibility.
Credit: https://github.com/cognitect/transit-format

Key Insight:
    UV/pip are EXECUTION tools - they install packages fast.
    keri-sec is the GOVERNANCE layer - it answers:
      - WHY is this version required?
      - WHO approved it?
      - WHEN can we change it?
      - WHAT's the audit trail?

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   Stack Registry                        │
    │  Constraint SAIDs with controller AIDs and audit trail  │
    └──────────────────────┬──────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────┐
    │             StackManager                                │
    │  - Defines stacks with cryptographic SAIDs              │
    │  - Verifies environment compliance via handlers         │
    │  - Generates pyproject.toml / requirements.txt          │
    │  - Invokes UV/pip for installation                      │
    └──────────────────────┬──────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────┐
    │              UV / pip                                   │
    │  Actually installs the governed versions                │
    └─────────────────────────────────────────────────────────┘

Usage:
    from keri_sec import StackManager, KERI_PRODUCTION_STACK

    # Create manager
    sm = StackManager()

    # Define a keri-sec stack
    stack = sm.define_stack(
        name="my-project",
        controller_aid="BMASTER_AID...",
        constraints=KERI_PRODUCTION_STACK,
        rationale="Production KERI deployment",
    )

    # Check compliance
    result = sm.check_compliance(stack.said)
    if not result.compliant:
        sm.install_with_uv(stack.said)

    # Generate pyproject.toml
    toml = sm.generate_pyproject(stack.said)

Handler System (Transit-inspired):
    from keri_sec import get_handler, register_handler, ConstraintHandler

    # Get existing handler
    python_handler = get_handler("python")

    # Register custom handler
    class DockerImageHandler(ConstraintHandler):
        ...
    register_handler("docker-image", DockerImageHandler())
"""

__version__ = "0.1.0"

# KERI Package Signing - Publisher identity for verification
# To verify this package:
#   1. Download: pip download keri-sec --no-deps
#   2. Get signature: curl -O https://github.com/WebOfTrust/keri-sec/releases/download/v0.1.0/keri_sec-0.1.0.sig.json
#   3. Verify: keri-git-said codesign verify keri_sec-0.1.0-py3-none-any.whl --credential keri_sec-0.1.0.sig.json
PUBLISHER_AID = "EFyO5GKXB6XgzhuvRFkOojvQOPDsa3_IndeXFhZcYnjL"

from keri_sec.manager import (
    StackManager,
    ConstraintType,
    Constraint,
    StackProfile,
    ComplianceResult,
    ConstraintCheck,
    get_stack_manager,
    reset_stack_manager,
)

from keri_sec.stacks import (
    KERI_PRODUCTION_STACK,
    KERI_DEV_STACK,
    KGQL_STACK,
    AI_ORCHESTRATOR_STACK,
    WITNESS_STACK,
    MINIMAL_STACK,
)

# Transit-inspired handler system
from keri_sec.handlers import (
    ConstraintHandler,
    VerificationResult,
    PythonVersionHandler,
    PackageHandler,
    SystemPackageHandler,
    BinaryHandler,
    get_handler,
    register_handler,
    list_handlers,
    HANDLERS,
)

# Caching system
from keri_sec.cache import (
    ConstraintCache,
    SAIDCache,
)

# Constraint type codes
from keri_sec.codes import (
    ConstraintCode,
    CONSTRAINT_CODES,
    encode_constraint,
    decode_constraint,
    is_ground_type,
)

# Extension support
from keri_sec.extensions import (
    UnknownConstraint,
    ExtensionConstraint,
    create_composite_constraint,
    is_extension,
)

# Streaming
from keri_sec.streaming import (
    OutputMode,
    MIME_TYPES,
    stream_constraints,
    serialize_stack,
)

# TEL Anchoring (optional - requires KERI infrastructure)
try:
    from keri_sec.tel_anchoring import (
        StackCredentialIssuer,
        CredentialIssuanceResult,
        get_issuer_from_session,
        create_issuer_with_keri,
        STACK_SCHEMA_SAID,
        WORKSPACE_SCHEMA_SAID,
    )
    _TEL_AVAILABLE = True
except ImportError:
    _TEL_AVAILABLE = False
    StackCredentialIssuer = None
    CredentialIssuanceResult = None
    get_issuer_from_session = None
    create_issuer_with_keri = None
    STACK_SCHEMA_SAID = None
    WORKSPACE_SCHEMA_SAID = None

# Environment Verification
from keri_sec.verification import (
    verify_environment,
    verify_or_fail,
    VerificationResult as EnvVerificationResult,
    InstallationCredential,
    PackageMismatch,
    EnvironmentVerificationPlugin,
)

# Lock File & Installation Credentials
from keri_sec.lock_file import (
    LockFile,
    ResolvedPackage,
    generate_lock_file,
    save_lock_file,
    load_lock_file,
    verify_lock_file,
    compute_said,
)

from keri_sec.installation_credential import (
    InstallationCredentialIssuer,
    InstallationCredentialData,
    IssuedCredential,
    create_installation_credential,
    issue_installation_credential,
    save_credential,
    load_credential,
)

# Algorithm DAIDs (GAID - Governed Algorithm Identifiers)
from keri_sec.algorithms import (
    AlgorithmCategory,
    AlgorithmDAID,
    AlgorithmDAIDRegistry,
    AlgorithmStatus,
    AlgorithmVersion,
    get_algorithm_daid_registry,
    reset_algorithm_daid_registry,
)

# Schema DAIDs (Governed ACDC Schemas)
from keri_sec.schemas import (
    SchemaDAID,
    SchemaDAIDRegistry,
    SchemaStatus,
    SchemaVersion,
    get_schema_registry,
    reset_schema_registry,
)

# DAID Verification (integrates Schema and Algorithm DAIDs)
from keri_sec.daid_verification import (
    DAIDVerifier,
    SchemaVerificationResult,
    AlgorithmVerificationResult,
    CredentialVerificationResult,
    verify_schema,
    check_algorithm,
    get_schema_said_for_issuance,
)

# Permission Parser (Claude Code settings analysis)
from keri_sec.permissions import (
    PermissionCategory,
    PermissionClass,
    PermissionEntry,
    PermissionParser,
    PermissionPolicy,
    PermissionAnalysis,
    ConsolidationSuggestion,
    PatternType,
)

# Package DAIDs (Supply Chain Security)
from keri_sec.packages import (
    PackageDAID,
    PackageDAIDRegistry,
    PackageStatus,
    PackageVersion,
    VerificationResult as PackageVerificationResult,
    get_package_daid_registry,
    reset_package_daid_registry,
)


def tel_available() -> bool:
    """Check if TEL anchoring is available."""
    return _TEL_AVAILABLE

__all__ = [
    # Manager
    "StackManager",
    "ConstraintType",
    "Constraint",
    "StackProfile",
    "ComplianceResult",
    "ConstraintCheck",
    "get_stack_manager",
    "reset_stack_manager",
    # Pre-defined stacks
    "KERI_PRODUCTION_STACK",
    "KERI_DEV_STACK",
    "KGQL_STACK",
    "AI_ORCHESTRATOR_STACK",
    "WITNESS_STACK",
    "MINIMAL_STACK",
    # Handlers (Transit-inspired)
    "ConstraintHandler",
    "VerificationResult",
    "PythonVersionHandler",
    "PackageHandler",
    "SystemPackageHandler",
    "BinaryHandler",
    "get_handler",
    "register_handler",
    "list_handlers",
    "HANDLERS",
    # Caching
    "ConstraintCache",
    "SAIDCache",
    # Codes
    "ConstraintCode",
    "CONSTRAINT_CODES",
    "encode_constraint",
    "decode_constraint",
    "is_ground_type",
    # Extensions
    "UnknownConstraint",
    "ExtensionConstraint",
    "create_composite_constraint",
    "is_extension",
    # Streaming
    "OutputMode",
    "MIME_TYPES",
    "stream_constraints",
    "serialize_stack",
    # TEL Anchoring
    "tel_available",
    "StackCredentialIssuer",
    "CredentialIssuanceResult",
    "get_issuer_from_session",
    "create_issuer_with_keri",
    "STACK_SCHEMA_SAID",
    "WORKSPACE_SCHEMA_SAID",
    # Environment Verification
    "verify_environment",
    "verify_or_fail",
    "EnvVerificationResult",
    "InstallationCredential",
    "PackageMismatch",
    "EnvironmentVerificationPlugin",
    # Lock Files
    "LockFile",
    "ResolvedPackage",
    "generate_lock_file",
    "save_lock_file",
    "load_lock_file",
    "verify_lock_file",
    "compute_said",
    # Installation Credentials
    "InstallationCredentialIssuer",
    "InstallationCredentialData",
    "IssuedCredential",
    "create_installation_credential",
    "issue_installation_credential",
    "save_credential",
    "load_credential",
    # Algorithm DAIDs (GAID)
    "AlgorithmCategory",
    "AlgorithmDAID",
    "AlgorithmDAIDRegistry",
    "AlgorithmStatus",
    "AlgorithmVersion",
    "get_algorithm_daid_registry",
    "reset_algorithm_daid_registry",
    # Schema DAIDs
    "SchemaDAID",
    "SchemaDAIDRegistry",
    "SchemaStatus",
    "SchemaVersion",
    "get_schema_registry",
    "reset_schema_registry",
    # DAID Verification
    "DAIDVerifier",
    "SchemaVerificationResult",
    "AlgorithmVerificationResult",
    "CredentialVerificationResult",
    "verify_schema",
    "check_algorithm",
    "get_schema_said_for_issuance",
    # Permission Parser
    "PermissionCategory",
    "PermissionClass",
    "PermissionEntry",
    "PermissionParser",
    "PermissionPolicy",
    "PermissionAnalysis",
    "ConsolidationSuggestion",
    "PatternType",
    # Package DAIDs (Supply Chain Security)
    "PackageDAID",
    "PackageDAIDRegistry",
    "PackageStatus",
    "PackageVersion",
    "PackageVerificationResult",
    "get_package_daid_registry",
    "reset_package_daid_registry",
]
