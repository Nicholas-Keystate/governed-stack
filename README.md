# Governed Stack

> **⚠️ HYPER-EXPERIMENTAL ⚠️**
>
> This package is in early development. The API may change without notice.
> Use at your own risk. Not recommended for production use.

KERI-governed dependency management - cryptographic source of truth for version constraints.

## Problem

Version truth fragmentation across your stack:

```
pyproject.toml:  requires-python = ">=3.10"
CI workflow:     python-version: "3.12.1"
README:          "Tested on Python 3.11+"
Production:      Actually running 3.10.4
Team Slack:      "Use 3.12, we need tomllib"
```

Five sources of "truth" → drift → bugs → security issues.

## Solution

**One cryptographic source of truth.**

```python
from governed_stack import StackManager, KERI_PRODUCTION_STACK

sm = StackManager()
stack = sm.define_stack(
    name="my-project",
    controller_aid="BMASTER_AID...",  # WHO can modify
    constraints=KERI_PRODUCTION_STACK,
    rationale="Production KERI deployment",
)

# Stack SAID: EABCDxyz... (cryptographic identifier)
# Every constraint has its own SAID
# Full audit trail of changes
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Stack Registry                        │
│  Constraint SAIDs with controller AIDs and audit trail  │
│  WHO approved? WHEN? WHY? → Cryptographic proof         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│             StackManager                                │
│  - define_stack() → creates SAIDs                       │
│  - check_compliance() → verifies environment            │
│  - generate_pyproject() → exports with SAID refs        │
│  - install_with_uv() → fast installation                │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              UV / pip                                   │
│  Actually installs the governed versions                │
└─────────────────────────────────────────────────────────┘
```

**Key Insight:** UV/pip are EXECUTION tools. Governed Stack is the GOVERNANCE layer.

## Installation

```bash
# ⚠️ HYPER-EXPERIMENTAL - API may change
pip install governed-stack

# Or with UV (recommended)
uv pip install governed-stack
```

## Quick Start

### CLI Usage

```bash
# Define a governed stack
governed-stack define my-project \
  --controller BMASTER_AID... \
  --stack keri

# Check compliance
governed-stack check my-project

# Install dependencies
governed-stack install my-project

# Generate pyproject.toml
governed-stack generate my-project --pyproject
```

### Python API

```python
from governed_stack import StackManager, KERI_PRODUCTION_STACK

# Create manager
sm = StackManager()

# Define a stack
stack = sm.define_stack(
    name="my-project",
    controller_aid="BMASTER_AID...",
    constraints={
        "python": ">=3.12",
        "keri": ">=1.2.0,<2.0.0",
        "hio": ">=0.6.14",
    },
    rationale="Production KERI deployment",
)

print(f"Stack SAID: {stack.said}")
# Stack SAID: EABCDxyz...

# Check compliance
result = sm.check_compliance(stack.said)
print(f"Compliant: {result.compliant}")

# Install if needed
if not result.compliant:
    success, output = sm.install_with_uv(stack.said)

# Generate pyproject.toml
toml = sm.generate_pyproject(stack.said)
print(toml)
```

## Pre-defined Stacks

| Stack | Description |
|-------|-------------|
| `MINIMAL_STACK` | Just Python + keri + hio |
| `KERI_PRODUCTION_STACK` | Full KERI production dependencies |
| `KERI_DEV_STACK` | Production + pytest, ruff, mypy |
| `KGQL_STACK` | KERI + lark for query language |
| `WITNESS_STACK` | KERI + aiohttp for witnesses |
| `AI_ORCHESTRATOR_STACK` | KERI + anthropic, openai |

## Generated Output

```toml
# GOVERNED STACK - Do not edit manually
# Stack: my-project
# SAID: EABCDxyz...
# Controller: BMASTER_AID...
# Generated: 2026-01-24T12:00:00+00:00

[project]
requires-python = ">=3.12"
# Constraint SAID: EConstraint1...

dependencies = [
    "hio>=0.6.14",  # SAID: EConstraint2...
    "keri>=1.2.0,<2.0.0",  # SAID: EConstraint3...
]
```

## Comparison: Traditional vs Governed

| Aspect | pyproject.toml / uv.lock | Governed Stack |
|--------|--------------------------|----------------|
| Source of Truth | File (can drift) | Cryptographic SAID |
| Who Approved? | Git blame (mutable) | Controller AID (KEL) |
| Audit Trail | Git history | Append-only chain |
| Breaking Changes | Semver honor system | Enforced notice period |
| Cross-Project Sync | Manual | SAID reference |
| Reproducibility | Lockfile | SAID + controller chain |

## Attack Scenarios (Tested)

These scenarios are implemented as tests in `tests/test_attack_scenarios.py`:

### 1. Tamper Detection

**Traditional:** Someone edits `pyproject.toml` to change a version. No cryptographic way to detect.

**Governed:** SAID verification fails immediately.

```python
# Verify pyproject.toml hasn't been modified
verified, said, _ = sm.verify_pyproject(pyproject_content)
if not verified:
    raise SecurityError("Dependencies have been tampered with!")
```

### 2. Silent Version Drift

**Traditional:** Dev has `keri==1.3.0`, prod has `keri==1.2.0`. Nobody notices.

**Governed:** All environments verify against the same SAID.

```python
# All environments use same SAID
CANONICAL_SAID = "EJhnw-FDaBvlhFCRAjTjxjJKBWx7vXEOITZYxYQD9g55"

# Each environment verifies before deploy
verified, _ = sm.verify_stack(
    expected_said=CANONICAL_SAID,
    name="myapp",
    controller_aid="BOPS_TEAM",
    constraints=current_constraints,
)
```

### 3. Supply Chain Attack

**Traditional:** Attacker injects malicious package or downgrades to vulnerable version.

**Governed:** Injection or downgrade changes SAID, verification fails.

```python
# Security team's approved constraints
approved = {"django": ">=4.2.0", "requests": ">=2.31.0"}

# Attacker tries to inject or downgrade
compromised = {"django": ">=4.2.0", "requests": ">=2.25.0", "evil-pkg": ">=1.0"}

# Different constraints = different SAID
assert compute_said(approved) != compute_said(compromised)
```

### 4. Unauthorized Modification

**Traditional:** Junior dev changes version, git blame shows who but not authorization.

**Governed:** Controller AID cryptographically bound. Unauthorized changes produce different SAID.

```python
# Only BSENIOR_ENGINEER_AID can produce this SAID
stack = sm.define_stack(
    name="company-stack",
    controller_aid="BSENIOR_ENGINEER_AID",
    constraints={"keri": ">=1.2.0"},
)

# Junior dev can't forge the SAID without the controller key
```

### 5. CI/CD Verification Workflow

```python
# In CI pipeline:
APPROVED_SAID = os.environ["APPROVED_STACK_SAID"]  # From secure config

# Load developer's pyproject.toml
with open("pyproject.toml") as f:
    content = f.read()

# Verify before deploy
verified, _, _ = sm.verify_pyproject(content, expected_said=APPROVED_SAID)
if not verified:
    sys.exit("DEPLOY BLOCKED: Dependencies don't match approved SAID")
```

## Verification API

```python
# Verify constraints produce expected SAID
verified, computed = sm.verify_stack(
    expected_said="EABCDxyz...",
    name="my-project",
    controller_aid="BMASTER_AID",
    constraints={"python": ">=3.12", "keri": ">=1.2.0"},
)

# Verify pyproject.toml (parses and checks embedded SAID)
verified, said, constraints = sm.verify_pyproject(pyproject_content)

# Verify requirements.txt
verified, said, constraints = sm.verify_requirements(requirements_content)
```

## Inspired By

This project synthesizes ideas from:

### KERI (Key Event Receipt Infrastructure) by Samuel M. Smith

- Self-certifying identifiers, SAIDs, TEL anchoring
- https://keri.one

### Transit by Cognitect (Rich Hickey et al.)

- Handler-based type extensibility
- Ground types vs extension types
- "No opaque blobs" principle
- Self-describing prefixes
- https://github.com/cognitect/transit-format

**Key Insight:** Transit solved semantic type preservation across language
boundaries. Governed Stack solves authorization preservation across
environment boundaries. Both reject central registries as trust anchors.

## Design Principles

### KERI Principles

This package follows Samuel Smith's KERI design principles:

1. **SAIDs for Content-Addressability** - Every constraint has a SAID derived from its content
2. **Controller AIDs for Authorization** - Only the controller can modify stack constraints
3. **Append-Only History** - Changes create new versions, never delete
4. **Deterministic Serialization** - JSON with sorted keys ensures reproducible SAIDs
5. **Blake3 for Performance** - Uses keripy's Diger with Blake3_256

### Transit Patterns

Handler-based extensibility inspired by Transit:

1. **Ground Types** - Built-in types with well-known verification (python, package, system, binary)
2. **Extension Types** - User-defined types that compose on ground types
3. **No Opaque Blobs** - Every constraint must decompose to verifiable primitives
4. **Self-Describing Codes** - CESR-aligned type codes embedded in encoded constraints
5. **Forward Compatibility** - Unknown types preserved for roundtrip serialization

## Extension Handlers

Register custom constraint handlers for specialized verification:

```python
from governed_stack import ConstraintHandler, register_handler, VerificationResult

class DockerImageHandler(ConstraintHandler):
    @property
    def code(self) -> str:
        return "D"  # Single-char code

    @property
    def type_name(self) -> str:
        return "docker-image"

    def serialize(self, name: str, spec: str) -> bytes:
        # Deterministic serialization for SAID computation
        import json
        data = {"handler": self.code, "type": self.type_name, "name": name, "spec": spec}
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def verify(self, name: str, spec: str) -> VerificationResult:
        # Check if Docker image exists with correct tag
        import subprocess
        result = subprocess.run(["docker", "images", "-q", f"{name}:{spec}"], capture_output=True)
        found = bool(result.stdout.strip())
        return VerificationResult(
            verified=found,
            constraint_said=self.compute_said(name, spec),
            actual_value=spec if found else "",
            expected_spec=spec,
            message="" if found else f"Docker image {name}:{spec} not found",
            handler_code=self.code,
        )

# Register the handler
register_handler("docker-image", DockerImageHandler())

# Now use it in stack definitions
stack = sm.define_stack(
    name="containerized-app",
    controller_aid="BMASTER...",
    constraints={
        "python": ">=3.12",
        "docker-image:myapp": "latest",  # Uses DockerImageHandler
    },
)
```

## Requirements

- Python >= 3.12
- keri >= 1.2.0
- hio >= 0.6.14
- libsodium (system dependency)

### Installing libsodium

```bash
# macOS
brew install libsodium

# Ubuntu/Debian
apt-get install libsodium-dev

# Fedora
dnf install libsodium-devel
```

## License

Apache-2.0

## Warning

> **⚠️ HYPER-EXPERIMENTAL ⚠️**
>
> This package is in early development. The API WILL change.
> Do not use in production without understanding the risks.
> This is a research project exploring KERI-governed dependency management.
