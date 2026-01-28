# -*- encoding: utf-8 -*-
"""
Extension Constraints - Transit-inspired forward compatibility.

Transit returns TaggedValue for unrecognized tags, preserving them for
roundtrip serialization. This module implements the same pattern for
constraint types.

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

Key patterns:
1. UnknownConstraint - Preserves unknown types for forward compatibility
2. ExtensionConstraint - User-defined types composing ground types
3. "No opaque blobs" - Extensions must decompose to verifiable primitives
"""

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from keri.core import coring


@dataclass
class UnknownConstraint:
    """
    Placeholder for constraint types without registered handlers.

    Transit pattern: Preserve unknown tags for roundtrip serialization.
    KERI pattern: Unknown constraints don't verify but don't fail parsing.

    This enables forward compatibility - a newer constraint type can be
    serialized by one system and deserialized by an older system that
    doesn't recognize the type. The older system preserves it for
    re-serialization without data loss.

    Attributes:
        tag: The unknown type tag
        value: The constraint value (preserved as-is)
        original_said: SAID from original encoding (if available)
    """

    tag: str
    value: Any
    original_said: Optional[str] = None

    def serialize(self) -> bytes:
        """
        Deterministic serialization preserving original structure.

        Uses Transit's tagged value format: {"~#": tag, "v": value}
        Keys are sorted for determinism.

        Returns:
            Deterministic byte representation
        """
        data = {
            "~#": self.tag,
            "v": self.value,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_said(self) -> str:
        """Compute SAID for this unknown constraint."""
        ser = self.serialize()
        diger = coring.Diger(ser=ser, code=coring.MtrDex.Blake3_256)
        return diger.qb64

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnknownConstraint):
            return False
        return self.tag == other.tag and self.value == other.value


@dataclass
class ExtensionConstraint:
    """
    User-defined constraint type composing ground types.

    Transit pattern: Extensions compose on ground types, never opaque.
    KERI pattern: Must decompose to verifiable primitives.

    Example:
        # A "keri-production" extension composes multiple package constraints
        keri_production = ExtensionConstraint(
            tag="keri-production",
            ground_type="package",
            constraints=[
                {"name": "keri", "version": ">=1.2.0"},
                {"name": "hio", "version": ">=0.6.14"},
            ],
            verification="all_installed",
        )

    Attributes:
        tag: Unique identifier for this extension type
        ground_type: The base type this composes ('package', 'system', etc.)
        constraints: List of ground-type constraints
        verification: Named verification strategy
        metadata: Optional additional data (must be serializable)
    """

    tag: str
    ground_type: str
    constraints: List[Dict[str, str]]
    verification: str = "all"  # 'all', 'any', 'custom'
    metadata: Dict[str, Any] = field(default_factory=dict)
    _custom_verifier: Optional[Callable] = field(default=None, repr=False)

    def serialize(self) -> bytes:
        """
        Deterministic serialization.

        Excludes _custom_verifier (not serializable).

        Returns:
            Deterministic byte representation
        """
        data = {
            "tag": self.tag,
            "ground_type": self.ground_type,
            "constraints": self.constraints,
            "verification": self.verification,
            "metadata": self.metadata,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_said(self) -> str:
        """Compute SAID for this extension constraint."""
        ser = self.serialize()
        diger = coring.Diger(ser=ser, code=coring.MtrDex.Blake3_256)
        return diger.qb64

    def set_custom_verifier(self, verifier: Callable[["ExtensionConstraint", dict], bool]) -> None:
        """
        Set custom verification function.

        The verifier receives (self, environment_dict) and returns bool.

        Args:
            verifier: Callable that performs verification
        """
        self._custom_verifier = verifier

    def decompose(self) -> List[Dict[str, str]]:
        """
        Decompose to ground-type constraints.

        Transit principle: No opaque blobs. Every extension must
        ultimately decompose to verifiable primitives.

        Returns:
            List of ground-type constraint dicts
        """
        return [
            {
                "type": self.ground_type,
                "name": c.get("name", ""),
                "spec": c.get("version", c.get("spec", "")),
            }
            for c in self.constraints
        ]


def create_composite_constraint(
    tag: str,
    includes: List[str],
    additional: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Create a composite constraint referencing other stacks by SAID.

    Transit pattern: Recursive composability.

    Example:
        composite = create_composite_constraint(
            tag="ai-orchestrator-full",
            includes=["ESAID_KERI_PRODUCTION...", "ESAID_AI_DEPS..."],
            additional={"anthropic": ">=0.40.0"},
        )

    Args:
        tag: Name for this composite
        includes: List of stack SAIDs to include
        additional: Additional constraints beyond includes

    Returns:
        Dict representing the composite constraint
    """
    return {
        "tag": tag,
        "type": "composite",
        "includes": includes,
        "additional": additional or {},
    }


def is_extension(constraint: Any) -> bool:
    """
    Check if constraint is an extension type.

    Args:
        constraint: Constraint to check

    Returns:
        True if extension (UnknownConstraint or ExtensionConstraint)
    """
    return isinstance(constraint, (UnknownConstraint, ExtensionConstraint))


def parse_unknown(data: Dict[str, Any]) -> Optional[UnknownConstraint]:
    """
    Parse Transit-style tagged value to UnknownConstraint.

    Args:
        data: Dict that may contain Transit tagged value

    Returns:
        UnknownConstraint if tagged value, None otherwise
    """
    if "~#" in data and "v" in data:
        return UnknownConstraint(tag=data["~#"], value=data["v"])
    return None
