# -*- encoding: utf-8 -*-
"""
Test credential handlers - Transit-inspired ACDC validation.

These tests explore when handler-based validation could replace
or complement JSON Schema validation for internal credentials.
"""

import pytest

from keri_sec.credential_handlers import (
    CredentialHandler,
    CredentialValidationResult,
    SessionCredentialHandler,
    TurnCredentialHandler,
    CapabilityCredentialHandler,
    get_credential_handler,
    register_credential_handler,
    validate_credential_fast,
    handler_to_json_schema,
    CREDENTIAL_HANDLERS,
)


class TestSessionCredentialHandler:
    """Test session credential handler."""

    def test_valid_session_credential(self):
        """Valid session credential passes validation."""
        handler = SessionCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESessionSAID...",
            "i": "EIssuerAID...",
            "s": "ESessionSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "session_id": "sess-001",
                "started_at": "2026-01-26T12:00:00Z",
                "capabilities": ["inference", "file_read"],
            },
        }

        result = handler.validate(credential)

        assert result.valid
        assert result.handler_type == "claude-session"
        assert len(result.errors) == 0

    def test_missing_session_id(self):
        """Missing session_id is caught by handler."""
        handler = SessionCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESessionSAID...",
            "i": "EIssuerAID...",
            "s": "ESessionSchema...",
            "a": {
                "d": "EAttrsSAID...",
                # session_id missing
            },
        }

        result = handler.validate(credential)

        assert not result.valid
        assert "session_id" in str(result.errors)

    def test_invalid_capabilities_type(self):
        """Capabilities must be a list."""
        handler = SessionCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESessionSAID...",
            "i": "EIssuerAID...",
            "s": "ESessionSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "session_id": "sess-001",
                "capabilities": "not-a-list",  # Wrong type
            },
        }

        result = handler.validate(credential)

        assert not result.valid
        assert "capabilities must be a list" in str(result.errors)


class TestTurnCredentialHandler:
    """Test turn credential handler."""

    def test_valid_turn_credential(self):
        """Valid turn credential passes validation."""
        handler = TurnCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ETurnSAID...",
            "i": "EIssuerAID...",
            "s": "ETurnSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "turn_number": 5,
                "session_said": "ESessionSAID...",
                "previous_turn_said": "EPrevTurnSAID...",
            },
        }

        result = handler.validate(credential)

        assert result.valid
        assert result.handler_type == "conversation-turn"

    def test_negative_turn_number(self):
        """Negative turn number is invalid."""
        handler = TurnCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ETurnSAID...",
            "i": "EIssuerAID...",
            "s": "ETurnSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "turn_number": -1,  # Invalid
                "session_said": "ESessionSAID...",
            },
        }

        result = handler.validate(credential)

        assert not result.valid
        assert "non-negative" in str(result.errors)


class TestCapabilityCredentialHandler:
    """Test capability credential handler."""

    def test_valid_capabilities(self):
        """Valid capabilities pass."""
        handler = CapabilityCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ECapSAID...",
            "i": "EIssuerAID...",
            "s": "ECapSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "capabilities": ["inference", "file_read", "bash"],
                "granted_to": "EAgentAID...",
            },
        }

        result = handler.validate(credential)

        assert result.valid

    def test_unknown_capability(self):
        """Unknown capabilities are rejected."""
        handler = CapabilityCredentialHandler()

        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ECapSAID...",
            "i": "EIssuerAID...",
            "s": "ECapSchema...",
            "a": {
                "d": "EAttrsSAID...",
                "capabilities": ["inference", "launch_missiles"],  # Invalid!
                "granted_to": "EAgentAID...",
            },
        }

        result = handler.validate(credential)

        assert not result.valid
        assert "launch_missiles" in str(result.errors)


class TestHandlerRegistry:
    """Test credential handler registry."""

    def test_get_known_handler(self):
        """Can get registered handlers."""
        handler = get_credential_handler("claude-session")
        assert handler is not None
        assert isinstance(handler, SessionCredentialHandler)

    def test_get_unknown_handler(self):
        """Unknown type returns None."""
        handler = get_credential_handler("unknown-type")
        assert handler is None

    def test_register_custom_handler(self):
        """Can register custom handlers."""
        class CustomHandler(CredentialHandler):
            @property
            def acdc_type(self):
                return "test-custom"

            def validate_attributes(self, attrs):
                return [] if "custom_field" in attrs else ["Missing custom_field"]

        register_credential_handler(CustomHandler())

        handler = get_credential_handler("test-custom")
        assert handler is not None

        # Clean up
        del CREDENTIAL_HANDLERS["test-custom"]


class TestFastValidation:
    """Test fast validation path."""

    def test_fast_validation_with_handler(self):
        """Fast validation uses handler when available."""
        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESomeSAID...",
            "i": "EIssuer...",
            "s": "ESchema...",
            "a": {
                "d": "EAttrs...",
                "type": "claude-session",  # Marker for handler lookup
                "session_id": "sess-001",
            },
        }

        result = validate_credential_fast(credential)

        assert result.handler_type == "claude-session"

    def test_fast_validation_without_handler(self):
        """Fast validation falls back for unknown types."""
        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESomeSAID...",
            "i": "EIssuer...",
            "s": "ESchema...",
            "a": {"type": "unknown-type"},
        }

        result = validate_credential_fast(credential)

        assert result.handler_type == "unknown"
        assert result.valid  # Basic structure is valid


class TestSchemaGeneration:
    """Test JSON Schema generation from handlers."""

    def test_generate_basic_schema(self):
        """Can generate JSON Schema from handler."""
        handler = SessionCredentialHandler()
        schema = handler_to_json_schema(handler)

        assert "$schema" in schema
        assert schema["type"] == "object"
        assert "v" in schema["properties"]
        assert "d" in schema["properties"]
        assert "a" in schema["properties"]

    def test_schema_has_title(self):
        """Generated schema has descriptive title."""
        handler = TurnCredentialHandler()
        schema = handler_to_json_schema(handler)

        assert "conversation-turn" in schema["title"]


class TestTransitKeriParadox:
    """
    Tests exploring the Transit vs KERI schema paradox.

    Key question: When should we use handler-based validation
    vs JSON Schema validation for ACDC credentials?
    """

    def test_handler_is_faster_than_schema_lookup(self):
        """
        Handler validation doesn't require schema resolution.

        This is Transit's key benefit: no lookup needed.
        """
        handler = SessionCredentialHandler()

        # Create valid credential
        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESAID...",
            "i": "EIssuer...",
            "s": "ESchema...",
            "a": {"d": "EAttrs...", "session_id": "sess-001"},
        }

        # Validation happens entirely in handler code
        # No schema fetch, no JSON Schema library invocation
        result = handler.validate(credential)

        assert result.valid

    def test_handler_defines_implicit_schema(self):
        """
        The handler's validate_attributes IS the schema definition.

        Fields checked = required fields
        Type checks = property types
        Value checks = property constraints
        """
        handler = CapabilityCredentialHandler()

        # The handler "knows":
        # - capabilities is required (list of specific values)
        # - granted_to is required (string)
        # - expires_at is optional

        # This knowledge IS the schema - just in code form
        valid_caps = handler.VALID_CAPABILITIES
        assert "inference" in valid_caps
        assert "bash" in valid_caps
        assert "launch_missiles" not in valid_caps

    def test_unknown_types_fall_through(self):
        """
        Unknown types can still be validated structurally.

        This is Transit's TaggedValue pattern applied to ACDC:
        Unknown types aren't rejected, just not deeply validated.
        """
        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESAID...",
            "i": "EIssuer...",
            "s": "EUnknownSchema...",
            "a": {
                "type": "future-credential-type",
                "some_field": "some_value",
            },
        }

        result = validate_credential_fast(credential)

        # Structure is valid, handler just didn't deeply validate
        assert result.valid
        assert result.handler_type == "unknown"

    def test_hybrid_mode_possible(self):
        """
        Handler can declare its schema SAID for hybrid mode.

        Internal validation: Use handler (fast)
        External sharing: Use schema SAID (interoperable)
        """
        class HybridHandler(CredentialHandler):
            @property
            def acdc_type(self):
                return "hybrid-example"

            @property
            def schema_said(self):
                # Real implementation would compute SAID from generated schema
                return "EHybridSchemaSAID..."

            def validate_attributes(self, attrs):
                return []

        handler = HybridHandler()

        # Handler has both:
        assert handler.acdc_type == "hybrid-example"  # Transit-style type
        assert handler.schema_said.startswith("E")     # KERI-style SAID

        # Validation can check schema matches
        credential = {
            "v": "ACDC10JSON000197_",
            "d": "ESAID...",
            "i": "EIssuer...",
            "s": "EHybridSchemaSAID...",  # Matches handler.schema_said
            "a": {},
        }

        result = handler.validate(credential)
        assert result.valid

        # Wrong schema SAID is caught
        credential["s"] = "EWrongSchema..."
        result = handler.validate(credential)
        assert not result.valid
        assert "Schema mismatch" in str(result.errors)
