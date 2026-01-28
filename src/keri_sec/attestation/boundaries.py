# -*- encoding: utf-8 -*-
"""
Trust Boundary Decorator - Automatic attestation at trust boundaries.

Usage:
    from keri_sec.attestation import trust_boundary, Tier

    @trust_boundary(
        tier=Tier.TEL_ANCHORED,
        schema_said=VERIFICATION_SCHEMA_SAID,
    )
    def verify_environment(stack_profile, issuer_hab):
        # Internal work happens here (no attestation)
        results = [handler.verify(c) for c in constraints]
        return {"verified": all(results), "count": len(results)}

    # When called, decorator:
    # 1. Computes input SAID
    # 2. Executes function
    # 3. Computes output SAID
    # 4. Creates attestation at specified tier
    # 5. Returns AttestableResult with result + attestation
"""

import functools
import inspect
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, TypeVar, Union

from .tiers import Tier, Attestation, create_attestation, compute_said

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class AttestableResult:
    """Result from an attestable function."""
    result: Any
    attestation: Optional[Attestation] = None
    input_said: Optional[str] = None
    output_said: Optional[str] = None

    @property
    def is_attested(self) -> bool:
        return self.attestation is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result,
            "attestation": self.attestation.to_dict() if self.attestation else None,
            "input_said": self.input_said,
            "output_said": self.output_said,
        }


def trust_boundary(
    tier: Tier = Tier.SAID_ONLY,
    schema_said: Optional[str] = None,
    description: str = "",
    attest_inputs: bool = True,
    attest_outputs: bool = True,
    issuer_param: str = "issuer_hab",
    credential_service_param: str = "credential_service",
):
    """
    Decorator to mark a function as a trust boundary.

    At trust boundaries, the function's execution is attested at the
    specified tier. This creates an audit trail without requiring
    attestation at every internal computation.

    Args:
        tier: Attestation tier (TEL_ANCHORED, KEL_ANCHORED, SAID_ONLY)
        schema_said: Schema SAID for TEL_ANCHORED attestations
        description: Human-readable description of what this boundary represents
        attest_inputs: Whether to include input SAID in attestation
        attest_outputs: Whether to include output SAID in attestation
        issuer_param: Parameter name for issuer Hab
        credential_service_param: Parameter name for credential service

    Returns:
        Decorated function that returns AttestableResult
    """
    def decorator(func: Callable[..., T]) -> Callable[..., AttestableResult]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> AttestableResult:
            # Extract issuer_hab from kwargs or args
            issuer_hab = kwargs.get(issuer_param)
            credential_service = kwargs.get(credential_service_param)

            # If not in kwargs, try to find in positional args
            if issuer_hab is None:
                sig = inspect.signature(func)
                params = list(sig.parameters.keys())
                if issuer_param in params:
                    idx = params.index(issuer_param)
                    if idx < len(args):
                        issuer_hab = args[idx]

            # Compute input SAID
            input_said = None
            if attest_inputs:
                try:
                    # Serialize args/kwargs for SAID
                    input_data = {
                        "args": [repr(a) for a in args],
                        "kwargs": {k: repr(v) for k, v in kwargs.items()
                                   if k not in (issuer_param, credential_service_param)},
                    }
                    input_said = compute_said(input_data)
                except Exception as e:
                    logger.debug(f"Could not compute input SAID: {e}")

            # Execute function
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                # Attest the error if we can
                error_content = {
                    "function": func.__name__,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "input_said": input_said,
                }
                try:
                    attestation = create_attestation(
                        tier=min(tier, Tier.KEL_ANCHORED),  # Don't TEL-anchor errors
                        content=error_content,
                        issuer_hab=issuer_hab,
                    )
                except Exception:
                    attestation = None
                raise

            # Compute output SAID
            output_said = None
            if attest_outputs:
                try:
                    if isinstance(result, dict):
                        output_said = compute_said(result)
                    else:
                        output_said = compute_said({"result": repr(result)})
                except Exception as e:
                    logger.debug(f"Could not compute output SAID: {e}")

            # Create attestation content
            attestation_content = {
                "function": func.__name__,
                "description": description or func.__doc__ or "",
                "outcome": "success",
            }
            if input_said:
                attestation_content["input_said"] = input_said
            if output_said:
                attestation_content["output_said"] = output_said

            # Add result summary if dict
            if isinstance(result, dict):
                for key in ["verified", "success", "count", "status"]:
                    if key in result:
                        attestation_content[key] = result[key]

            # Create attestation
            try:
                attestation = create_attestation(
                    tier=tier,
                    content=attestation_content,
                    issuer_hab=issuer_hab,
                    schema_said=schema_said,
                    credential_service=credential_service,
                )
            except Exception as e:
                logger.warning(f"Attestation creation failed: {e}")
                attestation = None

            return AttestableResult(
                result=result,
                attestation=attestation,
                input_said=input_said,
                output_said=output_said,
            )

        # Preserve original function for direct access
        wrapper.__wrapped__ = func
        wrapper._trust_boundary_tier = tier
        wrapper._trust_boundary_schema = schema_said

        return wrapper
    return decorator


def bypass_attestation(func: Callable[..., AttestableResult]) -> Callable[..., Any]:
    """
    Get the unwrapped function to bypass attestation.

    Useful for internal calls where attestation would be redundant.

    Usage:
        @trust_boundary(tier=Tier.TEL_ANCHORED)
        def verify_all(items):
            # Don't re-attest internal calls
            return [bypass_attestation(verify_one)(item) for item in items]
    """
    return getattr(func, '__wrapped__', func)
