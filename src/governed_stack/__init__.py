# -*- encoding: utf-8 -*-
"""
Governed Stack - KERI-Governed Dependency Management

HYPER-EXPERIMENTAL: This package is in early development.
API may change without notice. Use at your own risk.

Provides cryptographic source of truth for version constraints using KERI primitives.
Bridges governance with execution (UV, pip) without compromising security.

Inspired by Cognitect's Transit format for handler-based type extensibility.
Credit: https://github.com/cognitect/transit-format

Key Insight:
    UV/pip are EXECUTION tools - they install packages fast.
    Governed Stack is the GOVERNANCE layer - it answers:
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
    from governed_stack import StackManager, KERI_PRODUCTION_STACK

    # Create manager
    sm = StackManager()

    # Define a governed stack
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
    from governed_stack import get_handler, register_handler, ConstraintHandler

    # Get existing handler
    python_handler = get_handler("python")

    # Register custom handler
    class DockerImageHandler(ConstraintHandler):
        ...
    register_handler("docker-image", DockerImageHandler())
"""

__version__ = "0.1.0"

from governed_stack.manager import (
    StackManager,
    ConstraintType,
    Constraint,
    StackProfile,
    ComplianceResult,
    ConstraintCheck,
    get_stack_manager,
    reset_stack_manager,
)

from governed_stack.stacks import (
    KERI_PRODUCTION_STACK,
    KERI_DEV_STACK,
    KGQL_STACK,
    AI_ORCHESTRATOR_STACK,
    WITNESS_STACK,
    MINIMAL_STACK,
)

# Transit-inspired handler system
from governed_stack.handlers import (
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
from governed_stack.cache import (
    ConstraintCache,
    SAIDCache,
)

# Constraint type codes
from governed_stack.codes import (
    ConstraintCode,
    CONSTRAINT_CODES,
    encode_constraint,
    decode_constraint,
    is_ground_type,
)

# Extension support
from governed_stack.extensions import (
    UnknownConstraint,
    ExtensionConstraint,
    create_composite_constraint,
    is_extension,
)

# Streaming
from governed_stack.streaming import (
    OutputMode,
    MIME_TYPES,
    stream_constraints,
    serialize_stack,
)

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
]
