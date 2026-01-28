# -*- encoding: utf-8 -*-
"""
Credential Handlers - Transit-inspired ACDC validation.

EXPERIMENTAL: Exploring handler-based credential validation as alternative
to JSON Schema for well-known internal credential types.

The insight: For internal credentials with stable, well-known structure,
the handler CAN be the schema. No JSON Schema lookup needed.

This is NOT a replacement for JSON Schema in ACDC - it's an exploration
of when Transit patterns could simplify KERI credential handling.

Use cases:
- Session credentials (ephemeral, internal)
- Turn attestations (well-known structure)
- Capability grants (code-defined semantics)

NOT for:
- vLEI credentials (need formal, queryable schemas)
- Cross-org credentials (need shared schema reference)
- Regulatory credentials (need introspectable structure)
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from keri.core import coring


@dataclass
class CredentialValidationResult:
    """Result of handler-based credential validation."""
    valid: bool
    credential_said: str
    errors: List[str]
    handler_type: str


class CredentialHandler(ABC):
    """
    Abstract handler for credential validation.

    Transit-inspired: The handler IS the schema.
    KERI-aligned: Works with ACDC structure.

    For internal, well-known credential types where:
    - Structure is stable and code-defined
    - No need for JSON Schema introspection
    - Handler code travels with the application
    """

    @property
    @abstractmethod
    def acdc_type(self) -> str:
        """
        Credential type identifier.

        Like Transit's tag - identifies what kind of credential this is.
        Could be mapped to schema SAID for interop.
        """

    @property
    def schema_said(self) -> Optional[str]:
        """
        Optional schema SAID for hybrid mode.

        If provided, credential can be validated both ways:
        - Handler-based (fast, code-defined)
        - Schema-based (formal, introspectable)
        """
        return None

    @abstractmethod
    def validate_attributes(self, attributes: Dict[str, Any]) -> List[str]:
        """
        Validate credential attributes.

        Returns list of error messages (empty if valid).
        Handler defines what attributes are required and their constraints.
        """

    def validate(self, credential: Dict[str, Any]) -> CredentialValidationResult:
        """
        Validate full ACDC credential structure.

        Checks:
        1. ACDC envelope structure (v, d, i, s, a)
        2. Handler-specific attribute validation
        3. Optional schema SAID match
        """
        errors = []

        # Check ACDC envelope
        if "v" not in credential:
            errors.append("Missing version field 'v'")
        elif not credential["v"].startswith("ACDC"):
            errors.append(f"Invalid version: {credential['v']}")

        if "d" not in credential:
            errors.append("Missing SAID field 'd'")

        if "i" not in credential:
            errors.append("Missing issuer field 'i'")

        if "s" not in credential:
            errors.append("Missing schema field 's'")
        elif self.schema_said and credential["s"] != self.schema_said:
            errors.append(f"Schema mismatch: expected {self.schema_said}, got {credential['s']}")

        if "a" not in credential:
            errors.append("Missing attributes field 'a'")
        else:
            # Handler-specific validation
            attr_errors = self.validate_attributes(credential["a"])
            errors.extend(attr_errors)

        return CredentialValidationResult(
            valid=len(errors) == 0,
            credential_said=credential.get("d", ""),
            errors=errors,
            handler_type=self.acdc_type,
        )


# =============================================================================
# Example Handlers for Internal Credentials
# =============================================================================

class SessionCredentialHandler(CredentialHandler):
    """
    Handler for session credentials.

    Structure is well-known, internal, ephemeral.
    No JSON Schema needed - handler defines it all.
    """

    @property
    def acdc_type(self) -> str:
        return "claude-session"

    def validate_attributes(self, attrs: Dict[str, Any]) -> List[str]:
        errors = []

        # Required fields
        if "session_id" not in attrs:
            errors.append("Missing required field: session_id")

        if "d" not in attrs:
            errors.append("Missing attributes SAID 'd'")

        # Optional but typed fields
        if "started_at" in attrs and not isinstance(attrs["started_at"], str):
            errors.append("started_at must be ISO8601 string")

        if "capabilities" in attrs:
            if not isinstance(attrs["capabilities"], list):
                errors.append("capabilities must be a list")

        return errors


class TurnCredentialHandler(CredentialHandler):
    """
    Handler for conversation turn credentials.

    Each turn is attested. Structure is stable.
    Handler-based validation is faster than schema lookup.
    """

    @property
    def acdc_type(self) -> str:
        return "conversation-turn"

    def validate_attributes(self, attrs: Dict[str, Any]) -> List[str]:
        errors = []

        # Required fields
        required = ["d", "turn_number", "session_said"]
        for field in required:
            if field not in attrs:
                errors.append(f"Missing required field: {field}")

        # Type checks
        if "turn_number" in attrs:
            if not isinstance(attrs["turn_number"], int):
                errors.append("turn_number must be integer")
            elif attrs["turn_number"] < 0:
                errors.append("turn_number must be non-negative")

        # Chain validation (None is valid for first turn)
        if "previous_turn_said" in attrs:
            prev = attrs["previous_turn_said"]
            if prev is not None and not prev.startswith("E"):
                errors.append("previous_turn_said must be valid SAID or null")

        return errors


class CapabilityCredentialHandler(CredentialHandler):
    """
    Handler for capability grant credentials.

    Capabilities are code-defined enums.
    Handler knows all valid capabilities.
    """

    VALID_CAPABILITIES = {
        "inference", "file_read", "file_write", "bash",
        "web_fetch", "mcp_access", "credential_issue",
    }

    @property
    def acdc_type(self) -> str:
        return "capability-grant"

    def validate_attributes(self, attrs: Dict[str, Any]) -> List[str]:
        errors = []

        if "capabilities" not in attrs:
            errors.append("Missing required field: capabilities")
        else:
            caps = attrs["capabilities"]
            if not isinstance(caps, list):
                errors.append("capabilities must be a list")
            else:
                for cap in caps:
                    if cap not in self.VALID_CAPABILITIES:
                        errors.append(f"Unknown capability: {cap}")

        if "granted_to" not in attrs:
            errors.append("Missing required field: granted_to")

        if "expires_at" in attrs:
            # Could validate ISO8601 format here
            pass

        return errors


# =============================================================================
# Handler Registry
# =============================================================================

CREDENTIAL_HANDLERS: Dict[str, CredentialHandler] = {
    "claude-session": SessionCredentialHandler(),
    "conversation-turn": TurnCredentialHandler(),
    "capability-grant": CapabilityCredentialHandler(),
}


def get_credential_handler(acdc_type: str) -> Optional[CredentialHandler]:
    """Get handler for credential type."""
    return CREDENTIAL_HANDLERS.get(acdc_type)


def register_credential_handler(handler: CredentialHandler) -> None:
    """Register custom credential handler."""
    CREDENTIAL_HANDLERS[handler.acdc_type] = handler


def validate_credential_fast(credential: Dict[str, Any]) -> CredentialValidationResult:
    """
    Fast credential validation using handler if available.

    Falls back to basic ACDC structure check if no handler registered.

    This is the "Transit pattern" for ACDC:
    - Known types: Use handler (fast, no schema lookup)
    - Unknown types: Fall back to schema-based validation
    """
    # Try to determine type from schema or marker
    acdc_type = credential.get("a", {}).get("type")

    if acdc_type and acdc_type in CREDENTIAL_HANDLERS:
        handler = CREDENTIAL_HANDLERS[acdc_type]
        return handler.validate(credential)

    # No handler - basic validation only
    errors = []
    for field in ["v", "d", "i", "s", "a"]:
        if field not in credential:
            errors.append(f"Missing ACDC field: {field}")

    return CredentialValidationResult(
        valid=len(errors) == 0,
        credential_said=credential.get("d", ""),
        errors=errors,
        handler_type="unknown",
    )


# =============================================================================
# Bridge to JSON Schema (Hybrid Mode)
# =============================================================================

def handler_to_json_schema(handler: CredentialHandler) -> Dict[str, Any]:
    """
    Generate JSON Schema from handler.

    This enables hybrid mode:
    - Internal: Use handler (fast)
    - External: Use generated JSON Schema (introspectable)

    Note: This is a simplified generator. Real implementation would
    need to introspect handler.validate_attributes() more deeply.
    """
    # Basic ACDC structure
    schema = {
        "$id": handler.schema_said or f"urn:handler:{handler.acdc_type}",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"Handler-generated schema for {handler.acdc_type}",
        "type": "object",
        "required": ["v", "d", "i", "s", "a"],
        "properties": {
            "v": {"type": "string", "pattern": "^ACDC"},
            "d": {"type": "string"},
            "i": {"type": "string"},
            "s": {"type": "string"},
            "a": {"type": "object"},
        },
    }

    return schema
