# -*- encoding: utf-8 -*-
"""
Tests for Schema DAID - Governed ACDC Schema Management.

Verifies:
- Schema registration with DAID computation
- Resolution by DAID, qualified name, and content SAID
- Version rotation and version pinning
- Deprecation with successor references
"""

import pytest
from keri_sec.schemas import (
    SchemaDAID,
    SchemaDAIDRegistry,
    SchemaStatus,
    get_schema_registry,
    reset_schema_registry,
)


# Sample schema for testing
SAMPLE_SCHEMA = {
    "$id": "EPLACEHOLDER_SAID_____________________________",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Test Credential",
    "description": "A test credential schema",
    "type": "object",
    "credentialType": "TestCredential",
    "version": "1.0.0",
    "properties": {
        "v": {"type": "string"},
        "d": {"type": "string"},
        "i": {"type": "string"},
        "a": {
            "type": "object",
            "properties": {
                "testField": {"type": "string"}
            }
        }
    },
    "required": ["v", "d", "i", "a"]
}


class TestSchemaDAIDRegistry:
    """Test Schema DAID registration and resolution."""

    def setup_method(self):
        """Reset registry before each test."""
        reset_schema_registry()

    def test_register_schema(self):
        """Registering a schema computes DAID."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="test-credential",
            namespace="test-namespace",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        assert schema.daid.startswith("E")  # SAID prefix
        assert schema.name == "test-credential"
        assert schema.namespace == "test-namespace"
        assert schema.credential_type == "TestCredential"
        assert schema.status == SchemaStatus.ACTIVE
        assert len(schema.versions) == 1
        assert schema.current_version.version == "1.0.0"

    def test_qualified_name(self):
        """Schema has qualified name: namespace:name."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="skill-execution",
            namespace="ai-orchestrator",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        assert schema.qualified_name == "ai-orchestrator:skill-execution"

    def test_resolve_by_daid(self):
        """Can resolve by full DAID or prefix."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="test",
            namespace="ns",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        # Full DAID
        resolved = registry.resolve(schema.daid)
        assert resolved is not None
        assert resolved.name == "test"

        # Prefix match
        resolved = registry.resolve(schema.daid[:10])
        assert resolved is not None
        assert resolved.name == "test"

    def test_resolve_by_qualified_name(self):
        """Can resolve by namespace:name."""
        registry = SchemaDAIDRegistry()

        registry.register(
            name="skill-execution",
            namespace="ai-orchestrator",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        resolved = registry.resolve("ai-orchestrator:skill-execution")
        assert resolved is not None
        assert resolved.name == "skill-execution"

    def test_resolve_by_name_only(self):
        """Can resolve by name without namespace."""
        registry = SchemaDAIDRegistry()

        registry.register(
            name="unique-schema",
            namespace="some-namespace",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        resolved = registry.resolve("unique-schema")
        assert resolved is not None
        assert resolved.qualified_name == "some-namespace:unique-schema"

    def test_resolve_by_content_said(self):
        """Can resolve by content SAID."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="test",
            namespace="ns",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        content_said = schema.current_content_said
        resolved = registry.resolve(content_said)
        assert resolved is not None
        assert resolved.daid == schema.daid

    def test_daid_stable_through_rotation(self):
        """DAID remains stable through version rotations."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="evolving-schema",
            namespace="test",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )
        original_daid = schema.daid

        # Rotate to v1.1.0
        updated_schema = {**SAMPLE_SCHEMA, "version": "1.1.0"}
        updated_schema["properties"]["a"]["properties"]["newField"] = {"type": "string"}
        registry.rotate(
            daid=schema.daid,
            new_version="1.1.0",
            new_content=updated_schema,
            change_type="minor",
        )

        # DAID unchanged
        resolved = registry.resolve(original_daid)
        assert resolved.daid == original_daid
        assert len(resolved.versions) == 2
        assert resolved.current_version.version == "1.1.0"


class TestVersionPinning:
    """Test version pinning for credential issuance."""

    def setup_method(self):
        reset_schema_registry()

    def test_pin_version(self):
        """Can pin to specific schema version."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="pinnable",
            namespace="test",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        # Rotate to v2.0.0
        updated_schema = {**SAMPLE_SCHEMA, "version": "2.0.0"}
        registry.rotate(schema.daid, "2.0.0", updated_schema, "major")

        # Pin to v1.0.0
        v1_said = schema.pin_version("1.0.0")
        v2_said = schema.pin_version("2.0.0")

        assert v1_said != v2_said
        assert v2_said == schema.current_content_said

    def test_pin_nonexistent_version_raises(self):
        """Pinning to nonexistent version raises error."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="test",
            namespace="ns",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        with pytest.raises(ValueError, match="Version not found"):
            schema.pin_version("9.9.9")

    def test_version_history_preserved(self):
        """All versions remain accessible after rotations."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="versioned",
            namespace="test",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        registry.rotate(schema.daid, "1.1.0", {**SAMPLE_SCHEMA, "version": "1.1.0"}, "minor")
        registry.rotate(schema.daid, "2.0.0", {**SAMPLE_SCHEMA, "version": "2.0.0"}, "major",
                       breaking_changes=["Changed field format"])

        resolved = registry.resolve(schema.daid)
        versions = [v.version for v in resolved.versions]
        assert versions == ["1.0.0", "1.1.0", "2.0.0"]

        # Can get content for any version
        v1_content = registry.get_content_for_version(schema.daid, "1.0.0")
        assert v1_content["version"] == "1.0.0"


class TestSchemaDeprecation:
    """Test schema deprecation flow."""

    def setup_method(self):
        reset_schema_registry()

    def test_deprecation_with_successor(self):
        """Deprecating schema provides successor reference."""
        registry = SchemaDAIDRegistry()

        # Register old schema
        old_schema = registry.register(
            name="old-format",
            namespace="test",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        # Register new schema
        new_content = {**SAMPLE_SCHEMA, "title": "New Format"}
        new_schema = registry.register(
            name="new-format",
            namespace="test",
            version="1.0.0",
            content=new_content,
        )

        # Deprecate old in favor of new
        registry.deprecate(
            daid=old_schema.daid,
            reason="Superseded by new-format with better structure",
            successor_daid=new_schema.daid,
            deadline="2028-01-01T00:00:00Z",
        )

        # Verify deprecation state
        resolved = registry.resolve(old_schema.daid)
        assert resolved.is_deprecated
        assert resolved.status == SchemaStatus.DEPRECATED
        assert resolved.successor_daid == new_schema.daid
        assert resolved.deprecation.reason == "Superseded by new-format with better structure"

    def test_successor_resolution(self):
        """Can follow deprecation chain to successor."""
        registry = SchemaDAIDRegistry()

        old = registry.register("old", "ns", "1.0.0", SAMPLE_SCHEMA)
        new = registry.register("new", "ns", "1.0.0", {**SAMPLE_SCHEMA, "title": "New"})

        registry.deprecate(old.daid, "Replaced", new.daid)

        # Resolve old, get successor
        resolved_old = registry.resolve(old.daid)
        successor = registry.resolve(resolved_old.successor_daid)
        assert successor.name == "new"
        assert not successor.is_deprecated


class TestSchemaDAIDSerialization:
    """Test serialization for storage/transmission."""

    def test_to_dict(self):
        """Can serialize SchemaDAID to dict."""
        registry = SchemaDAIDRegistry()

        schema = registry.register(
            name="serializable",
            namespace="test-ns",
            version="1.0.0",
            content=SAMPLE_SCHEMA,
        )

        d = schema.to_dict()
        assert d["name"] == "serializable"
        assert d["namespace"] == "test-ns"
        assert d["qualified_name"] == "test-ns:serializable"
        assert d["credential_type"] == "TestCredential"
        assert d["status"] == "active"
        assert d["version_count"] == 1
        assert d["current_version"] == "1.0.0"
        assert d["current_content_said"] is not None


class TestListAndFilter:
    """Test listing and filtering schemas."""

    def setup_method(self):
        reset_schema_registry()

    def test_list_all_schemas(self):
        """Can list all registered schemas."""
        registry = SchemaDAIDRegistry()

        registry.register("schema-a", "ns1", "1.0.0", SAMPLE_SCHEMA)
        registry.register("schema-b", "ns1", "1.0.0", {**SAMPLE_SCHEMA, "title": "B"})
        registry.register("schema-c", "ns2", "1.0.0", {**SAMPLE_SCHEMA, "title": "C"})

        all_schemas = registry.list_schemas()
        assert len(all_schemas) == 3

    def test_filter_by_namespace(self):
        """Can filter schemas by namespace."""
        registry = SchemaDAIDRegistry()

        registry.register("a", "ns1", "1.0.0", SAMPLE_SCHEMA)
        registry.register("b", "ns1", "1.0.0", {**SAMPLE_SCHEMA, "title": "B"})
        registry.register("c", "ns2", "1.0.0", {**SAMPLE_SCHEMA, "title": "C"})

        ns1_schemas = registry.list_schemas(namespace="ns1")
        assert len(ns1_schemas) == 2
        assert all(s.namespace == "ns1" for s in ns1_schemas)
