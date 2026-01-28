# -*- encoding: utf-8 -*-
"""
KERI Runtime - Shared Infrastructure for Governed Development.

This module provides centralized KERI infrastructure management to prevent
singleton fracturing across projects. All KERI consumers should use these
exports rather than creating their own Habery/Regery instances.

Previously packaged as `keri-runtime`, now integrated into keri-sec
for unified KERI-governed development.

Usage:
    from keri_sec.keri import get_runtime, get_infrastructure

    runtime = get_runtime()
    if runtime.available:
        # Use runtime.hby, runtime.rgy, runtime.hab
        pass

    # Or get infrastructure directly
    infra = get_infrastructure()
    hab = infra.hby.makeHab(...)

Fracture Prevention:
    from keri_sec.keri import register_keri_consumer, check_for_fractures

    # Register your component as a KERI consumer
    register_keri_consumer("my_module", runtime.hby)

    # Check if multiple Habery instances exist (indicates fracture)
    fractures = check_for_fractures()
    if fractures.fractured:
        logger.warning(f"KERI fractures detected: {fractures}")

SAIDRef (SAID-based module references):
    from keri_sec.keri import resolve, register_module

    # Register a module
    said = register_module("my_package.module", "my_function", alias="my_func")

    # Resolve by SAID or alias (survives refactoring)
    func = resolve("my_func")

Credit:
    - KERI by Samuel M. Smith - https://keri.one
"""

from keri_sec.keri.infrastructure import (
    KeriInfrastructure,
    get_infrastructure,
    reset_infrastructure,
    KERI_AGENTS_PATH,
    AuditEntry,
    FileLock,
    compute_said,
    # Master AID integration
    master_aid_configured,
    get_master_aid_info,
    get_master_aid_prefix,
    MASTER_AID_CONFIG_PATH,
)

from keri_sec.keri.runtime import (
    KeriRuntime,
    get_runtime,
    initialize_runtime,
    reset_runtime,
    ensure_keri_available,
)

from keri_sec.keri.registry import (
    KeriConsumer,
    FractureReport,
    register_keri_consumer,
    get_registered_consumers,
    check_for_fractures,
    reset_registry,
)

from keri_sec.keri.said_ref import (
    resolve,
    register_module,
    deprecate,
    list_bindings,
    get_binding,
    verify_content,
    SAIDRefBinding,
    SAIDRefRegistry,
    SAID_REF_REGISTRY_PATH,
)

# Backward compatibility aliases
get_keri_runtime = get_runtime

__all__ = [
    # Infrastructure
    "KeriInfrastructure",
    "get_infrastructure",
    "reset_infrastructure",
    "KERI_AGENTS_PATH",
    "AuditEntry",
    "FileLock",
    "compute_said",
    # Master AID
    "master_aid_configured",
    "get_master_aid_info",
    "get_master_aid_prefix",
    "MASTER_AID_CONFIG_PATH",
    # Runtime
    "KeriRuntime",
    "get_runtime",
    "get_keri_runtime",  # Backward compat
    "initialize_runtime",
    "reset_runtime",
    "ensure_keri_available",
    # Fracture prevention
    "register_keri_consumer",
    "get_registered_consumers",
    "check_for_fractures",
    "reset_registry",
    "KeriConsumer",
    "FractureReport",
    # SAIDRef (SAID-based module references)
    "resolve",
    "register_module",
    "deprecate",
    "list_bindings",
    "get_binding",
    "verify_content",
    "SAIDRefBinding",
    "SAIDRefRegistry",
    "SAID_REF_REGISTRY_PATH",
]
