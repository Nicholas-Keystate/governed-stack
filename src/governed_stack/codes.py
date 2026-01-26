# -*- encoding: utf-8 -*-
"""
Constraint Type Codes - CESR-aligned, Transit-inspired.

CESR (Composable Event Streaming Representation) uses derivation codes
to make data self-describing. Transit uses tags for the same purpose.
This module defines codes for constraint types.

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

Pattern: Self-describing prefixes enable parsing without external schema.

    "P:>=3.12"        # Python version constraint
    "K:keri>=1.2.0"   # Package constraint
    "S:libsodium>=1.0.18"  # System package
    "B:kli>=0.6.8"    # Binary tool
    "X:custom:data"   # Extension type
"""

from enum import Enum
from typing import Dict, Optional, Tuple


class ConstraintCode(str, Enum):
    """
    CESR-style derivation codes for constraint types.

    Single-character codes for built-in (ground) types.
    'X' reserved for extension types.
    """

    PYTHON = "P"    # Python runtime version
    PACKAGE = "K"   # Python package (K for pacKage, P taken)
    SYSTEM = "S"    # System package (brew/apt)
    BINARY = "B"    # Binary tool in PATH
    EXTENSION = "X"  # User-defined extension


# Human-readable names for codes
CONSTRAINT_CODES: Dict[str, str] = {
    "P": "python",
    "K": "package",
    "S": "system",
    "B": "binary",
    "X": "extension",
}

# Reverse mapping: name to code
CONSTRAINT_NAMES: Dict[str, str] = {v: k for k, v in CONSTRAINT_CODES.items()}


def encode_constraint(type_name: str, name: str, spec: str) -> str:
    """
    Encode constraint with self-describing prefix.

    Transit pattern: Type is embedded in the value.

    Args:
        type_name: Constraint type ('python', 'package', etc.)
        name: Constraint name
        spec: Version specification

    Returns:
        Encoded string with type prefix

    Examples:
        encode_constraint('python', 'python', '>=3.12') → 'P:>=3.12'
        encode_constraint('package', 'keri', '>=1.2.0') → 'K:keri>=1.2.0'
    """
    code = CONSTRAINT_NAMES.get(type_name, "X")

    if type_name == "python":
        # Python constraints don't need name prefix
        return f"{code}:{spec}"
    elif type_name == "extension":
        # Extensions include subtype
        return f"{code}:{name}:{spec}"
    else:
        # Standard: code:name+spec
        return f"{code}:{name}{spec}"


def decode_constraint(encoded: str) -> Tuple[str, str, str]:
    """
    Decode self-describing constraint string.

    Args:
        encoded: Encoded constraint (e.g., 'K:keri>=1.2.0')

    Returns:
        Tuple of (type_name, name, spec)

    Raises:
        ValueError: If encoding is invalid
    """
    if ":" not in encoded:
        raise ValueError(f"Invalid constraint encoding: {encoded}")

    code = encoded[0]
    rest = encoded[2:]  # Skip code and colon

    type_name = CONSTRAINT_CODES.get(code)
    if not type_name:
        raise ValueError(f"Unknown constraint code: {code}")

    if type_name == "python":
        return (type_name, "python", rest)
    elif type_name == "extension":
        # Extensions: X:subtype:spec
        parts = rest.split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid extension encoding: {encoded}")
        return (type_name, parts[0], parts[1])
    else:
        # Parse name and spec from rest
        # Find first comparison operator
        for op in [">=", "<=", "==", "!=", "~=", ">", "<"]:
            if op in rest:
                idx = rest.index(op)
                name = rest[:idx]
                spec = rest[idx:]
                return (type_name, name, spec)

        # No operator found - treat as exact version
        # e.g., "K:keri1.2.0" (unusual but valid)
        return (type_name, rest, "")


def is_ground_type(type_name: str) -> bool:
    """
    Check if type is a ground (built-in) type.

    Ground types have well-known verification semantics.
    Extension types compose on ground types.

    Args:
        type_name: Type to check

    Returns:
        True if ground type, False if extension
    """
    return type_name in ("python", "package", "system", "binary")


def get_code(type_name: str) -> str:
    """
    Get code for type name.

    Args:
        type_name: Human-readable type name

    Returns:
        Single-character code

    Raises:
        ValueError: If type name is unknown
    """
    code = CONSTRAINT_NAMES.get(type_name)
    if not code:
        raise ValueError(f"Unknown constraint type: {type_name}")
    return code


def get_type_name(code: str) -> str:
    """
    Get type name for code.

    Args:
        code: Single-character code

    Returns:
        Human-readable type name

    Raises:
        ValueError: If code is unknown
    """
    name = CONSTRAINT_CODES.get(code)
    if not name:
        raise ValueError(f"Unknown constraint code: {code}")
    return name
