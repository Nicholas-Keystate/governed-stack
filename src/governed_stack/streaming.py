# -*- encoding: utf-8 -*-
"""
Streaming-Friendly Constraint Encoding.

Transit supports streaming without requiring an enclosing envelope.
This module provides similar capabilities for constraint encoding.

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

Key patterns:
1. OutputMode - Verbose (debug) vs Compact (production) vs CESR (binary)
2. MIME types - Content type declaration for interoperability
3. Streaming - Incremental encoding without wrapper envelope
"""

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional

from keri.core import coring


class OutputMode(Enum):
    """
    Output mode for constraint serialization.

    Transit provides JSON-Verbose and JSON (cached/compact).
    We add CESR for KERI-native binary encoding.
    """

    COMPACT = "compact"    # SAIDs only, cache codes, minimal
    VERBOSE = "verbose"    # Full constraint details, human-readable
    CESR = "cesr"          # CESR-native binary encoding


# MIME types for governed constraint formats
MIME_TYPES: Dict[str, str] = {
    "json": "application/governed-stack+json",
    "cesr": "application/governed-stack+cesr",
    "toml": "application/governed-stack+toml",
}


@dataclass
class StreamConfig:
    """Configuration for streaming output."""

    mode: OutputMode = OutputMode.COMPACT
    include_saids: bool = True
    include_rationale: bool = False
    line_separator: str = "\n"


def stream_constraints(
    constraints: List[Dict[str, Any]],
    config: Optional[StreamConfig] = None,
) -> Iterator[bytes]:
    """
    Yield encoded constraints for streaming.

    Transit-style: No wrapper envelope - each constraint is self-framing.
    Consumer can process incrementally without buffering entire stream.

    Args:
        constraints: List of constraint dicts
        config: Stream configuration

    Yields:
        Encoded constraint bytes
    """
    config = config or StreamConfig()

    for constraint in constraints:
        if config.mode == OutputMode.VERBOSE:
            # Full JSON with indentation
            encoded = json.dumps(constraint, indent=2, sort_keys=True)
            yield (encoded + config.line_separator).encode("utf-8")

        elif config.mode == OutputMode.COMPACT:
            # Minimal JSON, single line
            if config.include_saids:
                encoded = json.dumps(constraint, sort_keys=True, separators=(",", ":"))
            else:
                # Remove SAID fields for compactness
                filtered = {k: v for k, v in constraint.items() if k != "said"}
                encoded = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
            yield (encoded + config.line_separator).encode("utf-8")

        elif config.mode == OutputMode.CESR:
            # CESR binary encoding
            yield _cesr_encode_constraint(constraint)


def _cesr_encode_constraint(constraint: Dict[str, Any]) -> bytes:
    """
    Encode constraint in CESR format.

    Uses KERI's CESR encoding for self-framing binary.

    Args:
        constraint: Constraint dict

    Returns:
        CESR-encoded bytes
    """
    # For now, use JSON + SAID as CESR-like format
    # Full CESR would require proper count codes and framing
    json_bytes = json.dumps(constraint, sort_keys=True, separators=(",", ":")).encode("utf-8")
    diger = coring.Diger(ser=json_bytes, code=coring.MtrDex.Blake3_256)

    # Simple framing: SAID + content
    return diger.qb64b + b":" + json_bytes


def serialize_stack(
    stack: Dict[str, Any],
    mode: OutputMode,
) -> bytes:
    """
    Serialize entire stack in specified mode.

    Args:
        stack: Stack profile dict
        mode: Output mode

    Returns:
        Serialized stack bytes
    """
    if mode == OutputMode.VERBOSE:
        return json.dumps(stack, indent=2, sort_keys=True).encode("utf-8")

    elif mode == OutputMode.COMPACT:
        return json.dumps(stack, sort_keys=True, separators=(",", ":")).encode("utf-8")

    elif mode == OutputMode.CESR:
        # CESR mode: framed binary
        return _cesr_encode_constraint(stack)

    else:
        raise ValueError(f"Unknown output mode: {mode}")


def parse_stream(
    stream: Iterator[bytes],
    mode: OutputMode = OutputMode.COMPACT,
) -> Iterator[Dict[str, Any]]:
    """
    Parse constraint stream.

    Args:
        stream: Iterator of encoded constraint bytes
        mode: Expected encoding mode

    Yields:
        Parsed constraint dicts
    """
    for chunk in stream:
        if mode == OutputMode.CESR:
            # Parse CESR framing
            constraint = _cesr_decode_constraint(chunk)
        else:
            # JSON modes
            text = chunk.decode("utf-8").strip()
            if text:
                constraint = json.loads(text)
            else:
                continue

        yield constraint


def _cesr_decode_constraint(data: bytes) -> Dict[str, Any]:
    """
    Decode CESR-encoded constraint.

    Args:
        data: CESR-encoded bytes

    Returns:
        Constraint dict
    """
    # Find separator
    sep_idx = data.index(b":")
    said_bytes = data[:sep_idx]
    json_bytes = data[sep_idx + 1:]

    # Verify SAID
    diger = coring.Diger(ser=json_bytes, code=coring.MtrDex.Blake3_256)
    if diger.qb64b != said_bytes:
        raise ValueError("SAID verification failed")

    return json.loads(json_bytes)


def get_mime_type(format_name: str) -> str:
    """
    Get MIME type for format.

    Args:
        format_name: Format name ('json', 'cesr', 'toml')

    Returns:
        MIME type string
    """
    return MIME_TYPES.get(format_name, "application/octet-stream")


def detect_format(content_type: str) -> OutputMode:
    """
    Detect output mode from content type.

    Args:
        content_type: MIME type string

    Returns:
        Corresponding OutputMode
    """
    if "cesr" in content_type:
        return OutputMode.CESR
    elif "json" in content_type:
        return OutputMode.COMPACT
    else:
        return OutputMode.VERBOSE
