# -*- encoding: utf-8 -*-
"""
Pre-defined Stack Profiles

Standard constraint sets for common KERI deployment scenarios.
Use these as templates or extend with your own constraints.

HYPER-EXPERIMENTAL: These stacks may change as KERI evolves.
"""

# Minimal KERI stack - just the essentials
MINIMAL_STACK = {
    "python": ">=3.12",
    "keri": ">=1.2.0",
    "hio": ">=0.6.14",
}

# Full KERI production stack
KERI_PRODUCTION_STACK = {
    "python": ">=3.12",
    "keri": ">=1.2.0,<2.0.0",
    "hio": ">=0.6.14",
    "lark": ">=1.1.0",
    "msgpack": ">=1.0.0",
    "cbor2": ">=5.4.0",
    "pysodium": ">=0.7.12",
    "blake3": ">=0.3.0",
    "multidict": ">=6.0.0",
    "falcon": ">=3.1.0",
    "multicommand": ">=1.0.0",
}

# KERI development stack (production + dev tools)
KERI_DEV_STACK = {
    **KERI_PRODUCTION_STACK,
    "pytest": ">=7.0.0",
    "pytest-cov": ">=4.0.0",
    "ruff": ">=0.1.0",
    "mypy": ">=1.0.0",
}

# KGQL (KERI Graph Query Language) stack
KGQL_STACK = {
    **KERI_PRODUCTION_STACK,
    "lark": ">=1.1.0",  # Parser for query language
}

# Witness network stack
WITNESS_STACK = {
    **KERI_PRODUCTION_STACK,
    "aiohttp": ">=3.8.0",
    "requests": ">=2.28.0",
}

# AI Orchestrator stack (KERI + LLM backends)
AI_ORCHESTRATOR_STACK = {
    **KERI_PRODUCTION_STACK,
    "anthropic": ">=0.18.0",
    "openai": ">=1.0.0",
    "tiktoken": ">=0.5.0",
    "numpy": ">=1.24.0",
}
