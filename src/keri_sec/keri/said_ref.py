# -*- encoding: utf-8 -*-
"""
SAIDRef - SAID-based Module References.

This module provides content-addressed imports that survive refactoring.
Instead of importing by path (which breaks when files move), import by SAID
(which stays stable as long as the content/interface is unchanged).

NOTE: This is NOT a DAID (Document Autonomic IDentifier). DAIDs are stable
document identifiers that survive content rotation (like AIDs survive key
rotation). SAIDRef is simpler - just SAID-based module lookups.

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                      SAIDRef Resolver                           │
    │  - Maintains SAID → module path registry                        │
    │  - Provides resolve() for content-addressed imports             │
    │  - Supports interface SAIDs (stable across implementations)     │
    └─────────────────────────────────────────────────────────────────┘

Problem:
    When you refactor (move files, rename modules), imports break:

    # Before refactor:
    from my_project.utils.infrastructure import get_infrastructure

    # After moving to keri-sec:
    from keri_sec.keri import get_infrastructure  # ALL CALLERS MUST UPDATE

Solution:
    Use content-addressed imports that resolve via SAID:

    # This never changes, even when the implementation moves:
    get_infrastructure = resolve("EGet_Infrastructure_SAID...")

Two SAID Types:
    1. Content SAID: Hash of actual implementation (changes with any edit)
    2. Interface SAID: Hash of function signature/contract (stable across refactors)

    For refactoring, we use Interface SAIDs - they only change when the
    API contract changes, not when implementation details change.

Usage:
    from keri_sec.keri import resolve, register_module

    # Register a module with its interface SAID
    register_module(
        module_path="keri_sec.keri.infrastructure",
        attr="get_infrastructure",
        alias="get_infrastructure",
    )

    # Resolve by SAID (works even after refactoring)
    get_infrastructure = resolve("EGet_Infrastructure...")

    # Or by alias
    get_infrastructure = resolve("get_infrastructure")
"""

import hashlib
import importlib
import inspect
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Registry file location
SAID_REF_REGISTRY_PATH = Path.home() / ".keri" / "said_ref" / "registry.json"


@dataclass
class SAIDRefBinding:
    """A binding from SAID to module location."""
    said: str  # Interface SAID (stable)
    content_said: Optional[str] = None  # Content SAID (changes with edits)
    module_path: str = ""  # Python module path
    attr: Optional[str] = None  # Attribute within module (function, class)
    version: str = "1.0.0"  # Semantic version
    deprecated: bool = False
    deprecated_by: Optional[str] = None  # SAID of replacement
    registered_at: str = ""


@dataclass
class SAIDRefRegistry:
    """Registry of SAID → module bindings."""
    bindings: Dict[str, SAIDRefBinding] = field(default_factory=dict)
    aliases: Dict[str, str] = field(default_factory=dict)  # Short name → SAID


# Module-level singleton
_registry: Optional[SAIDRefRegistry] = None
_registry_lock = threading.Lock()


def _compute_interface_said(func: Callable) -> str:
    """
    Compute interface SAID for a function/class.

    The interface SAID is based on:
    - Function name
    - Parameter names and annotations
    - Return type annotation
    - Docstring (first line only - the contract)

    This is STABLE across refactoring as long as the API contract is unchanged.
    """
    sig = inspect.signature(func)

    # Build interface descriptor
    interface = {
        "name": func.__name__,
        "params": [],
        "return": str(sig.return_annotation) if sig.return_annotation != inspect.Parameter.empty else None,
        "doc": (func.__doc__ or "").split("\n")[0].strip(),  # First line only
    }

    for name, param in sig.parameters.items():
        param_info = {"name": name}
        if param.annotation != inspect.Parameter.empty:
            param_info["type"] = str(param.annotation)
        if param.default != inspect.Parameter.empty:
            param_info["has_default"] = True
        interface["params"].append(param_info)

    # Compute SAID using Blake2b
    content = json.dumps(interface, sort_keys=True, separators=(",", ":"))
    digest = hashlib.blake2b(content.encode(), digest_size=32).digest()

    # Return base64url-encoded with 'E' prefix (KERI convention)
    import base64
    b64 = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"E{b64[:43]}"  # 44 chars total (E + 43 base64)


def _compute_content_said(source: str) -> str:
    """Compute content SAID from source code."""
    digest = hashlib.blake2b(source.encode(), digest_size=32).digest()
    import base64
    b64 = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"E{b64[:43]}"


def _load_registry() -> SAIDRefRegistry:
    """Load or create the SAIDRef registry."""
    global _registry

    with _registry_lock:
        if _registry is not None:
            return _registry

        if SAID_REF_REGISTRY_PATH.exists():
            try:
                data = json.loads(SAID_REF_REGISTRY_PATH.read_text())
                bindings = {}
                for said, binding_data in data.get("bindings", {}).items():
                    bindings[said] = SAIDRefBinding(**binding_data)
                _registry = SAIDRefRegistry(
                    bindings=bindings,
                    aliases=data.get("aliases", {}),
                )
            except Exception as e:
                logger.warning(f"Failed to load SAIDRef registry: {e}")
                _registry = SAIDRefRegistry()
        else:
            _registry = SAIDRefRegistry()

        return _registry


def _save_registry() -> None:
    """Save the SAIDRef registry to disk."""
    global _registry

    if _registry is None:
        return

    SAID_REF_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "bindings": {
            said: {
                "said": b.said,
                "content_said": b.content_said,
                "module_path": b.module_path,
                "attr": b.attr,
                "version": b.version,
                "deprecated": b.deprecated,
                "deprecated_by": b.deprecated_by,
                "registered_at": b.registered_at,
            }
            for said, b in _registry.bindings.items()
        },
        "aliases": _registry.aliases,
    }

    SAID_REF_REGISTRY_PATH.write_text(json.dumps(data, indent=2))


def register_module(
    module_path: str,
    attr: Optional[str] = None,
    said: Optional[str] = None,
    alias: Optional[str] = None,
    version: str = "1.0.0",
) -> str:
    """
    Register a module/function with SAIDRef resolver.

    Args:
        module_path: Python module path (e.g., "keri_runtime.infrastructure")
        attr: Attribute within module (e.g., "get_infrastructure")
        said: Explicit interface SAID (computed if not provided)
        alias: Short name for the SAID (e.g., "get_infrastructure")
        version: Semantic version

    Returns:
        The interface SAID for this module/function
    """
    from datetime import datetime, timezone

    registry = _load_registry()

    # Import the module to get the actual object
    module = importlib.import_module(module_path)
    obj = getattr(module, attr) if attr else module

    # Compute interface SAID if not provided
    if said is None:
        if callable(obj):
            said = _compute_interface_said(obj)
        else:
            # For modules/non-callables, use module path as interface
            content = f"{module_path}:{attr}" if attr else module_path
            digest = hashlib.blake2b(content.encode(), digest_size=32).digest()
            import base64
            b64 = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            said = f"E{b64[:43]}"

    # Compute content SAID
    content_said = None
    try:
        source = inspect.getsource(obj)
        content_said = _compute_content_said(source)
    except (TypeError, OSError):
        pass  # Built-in or C extension

    # Create binding
    binding = SAIDRefBinding(
        said=said,
        content_said=content_said,
        module_path=module_path,
        attr=attr,
        version=version,
        registered_at=datetime.now(timezone.utc).isoformat(),
    )

    with _registry_lock:
        registry.bindings[said] = binding
        if alias:
            registry.aliases[alias] = said

    _save_registry()

    logger.debug(f"Registered SAIDRef: {alias or attr or module_path} -> {said[:16]}...")
    return said


def resolve(said_or_alias: str) -> Any:
    """
    Resolve a SAID or alias to the actual Python object.

    Args:
        said_or_alias: Either a full SAID (E...) or a registered alias

    Returns:
        The resolved Python object (function, class, module)

    Raises:
        KeyError: If SAID/alias not found
        ImportError: If module can't be imported

    Usage:
        # By SAID
        get_infrastructure = resolve("EGet_Infrastructure_SAID...")

        # By alias
        get_infrastructure = resolve("get_infrastructure")
    """
    registry = _load_registry()

    # Check if it's an alias
    if said_or_alias in registry.aliases:
        said = registry.aliases[said_or_alias]
    else:
        said = said_or_alias

    # Look up binding
    if said not in registry.bindings:
        # Try prefix match (first 8+ chars)
        if len(said) >= 8:
            matches = [s for s in registry.bindings if s.startswith(said)]
            if len(matches) == 1:
                said = matches[0]
            elif len(matches) > 1:
                raise KeyError(f"Ambiguous SAID prefix: {said} matches {matches}")

    if said not in registry.bindings:
        raise KeyError(f"SAIDRef not found: {said_or_alias}")

    binding = registry.bindings[said]

    # Check for deprecation
    if binding.deprecated:
        if binding.deprecated_by:
            logger.warning(
                f"SAIDRef {said[:16]}... is deprecated. "
                f"Use {binding.deprecated_by[:16]}... instead."
            )
        else:
            logger.warning(f"SAIDRef {said[:16]}... is deprecated.")

    # Import and resolve
    module = importlib.import_module(binding.module_path)
    if binding.attr:
        return getattr(module, binding.attr)
    return module


def deprecate(said: str, replacement_said: Optional[str] = None) -> None:
    """
    Mark a SAIDRef as deprecated.

    Args:
        said: The SAID to deprecate
        replacement_said: Optional SAID of the replacement
    """
    registry = _load_registry()

    if said not in registry.bindings:
        raise KeyError(f"SAIDRef not found: {said}")

    with _registry_lock:
        registry.bindings[said].deprecated = True
        registry.bindings[said].deprecated_by = replacement_said

    _save_registry()


def list_bindings() -> List[SAIDRefBinding]:
    """List all registered SAIDRef bindings."""
    registry = _load_registry()
    return list(registry.bindings.values())


def get_binding(said_or_alias: str) -> Optional[SAIDRefBinding]:
    """Get a specific binding by SAID or alias."""
    registry = _load_registry()

    if said_or_alias in registry.aliases:
        said = registry.aliases[said_or_alias]
    else:
        said = said_or_alias

    return registry.bindings.get(said)


def verify_content(said: str) -> Tuple[bool, Optional[str]]:
    """
    Verify that the current content matches the registered content SAID.

    Returns:
        (verified, current_said) - verified is True if content matches
    """
    registry = _load_registry()

    if said not in registry.bindings:
        return False, None

    binding = registry.bindings[said]

    if not binding.content_said:
        return True, None  # No content SAID to verify

    # Import and get current source
    try:
        module = importlib.import_module(binding.module_path)
        obj = getattr(module, binding.attr) if binding.attr else module
        source = inspect.getsource(obj)
        current_said = _compute_content_said(source)
        return current_said == binding.content_said, current_said
    except Exception:
        return False, None


def reset_registry() -> None:
    """Reset the SAIDRef registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
    if SAID_REF_REGISTRY_PATH.exists():
        SAID_REF_REGISTRY_PATH.unlink()
