# -*- encoding: utf-8 -*-
"""
Schema Registry - DAID-Governed Schema Management.

Provides registration and versioning of ACDC schemas with DAID identity.

Usage:
    from keri_sec.schemas import SchemaDAIDRegistry, get_schema_registry

    registry = get_schema_registry()

    # Register a schema
    schema_daid = registry.register(
        name="skill-execution",
        namespace="ai-orchestrator",
        version="1.0.0",
        content=schema_json,
    )

    # Resolve by DAID, name, or content SAID
    schema = registry.resolve("EDSCHEMA_SKILL_EXEC...")
    schema = registry.resolve("ai-orchestrator:skill-execution")

    # Pin credential issuance to specific version
    credential = issue_credential(schema_said=schema.pin_version("1.0.0"))
"""

from .registry import (
    SchemaDAID,
    SchemaDAIDRegistry,
    SchemaStatus,
    SchemaVersion,
    DeprecationNotice,
    get_schema_registry,
    reset_schema_registry,
)

__all__ = [
    "SchemaDAID",
    "SchemaDAIDRegistry",
    "SchemaStatus",
    "SchemaVersion",
    "DeprecationNotice",
    "get_schema_registry",
    "reset_schema_registry",
]
