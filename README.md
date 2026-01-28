# keri-sec

Cryptographic dependency security for Python. Every version constraint gets a SAID. Every change gets an AID.

## What it does

Your `pyproject.toml` says `keri>=1.2.0`. Someone changes it to `keri>=1.1.0`. Git blame tells you who. keri-sec tells you whether they were *authorized* to.

```python
from keri_sec import StackManager

sm = StackManager()
stack = sm.define_stack(
    name="my-project",
    controller_aid="EController...",  # Transferable AID — who can modify
    constraints={
        "python": ">=3.12",
        "keri": ">=1.2.0,<2.0.0",
        "hio": ">=0.6.14",
    },
)

# Stack SAID: EABCDxyz...
# Every constraint has its own SAID
# Controller AID bound via KEL — unforgeable
```

Any change to any constraint produces a different SAID. No controller key, no valid SAID.

## Why

| | pyproject.toml / uv.lock | keri-sec |
|--|--------------------------|----------|
| Source of truth | File (can drift) | Cryptographic SAID |
| Who approved? | Git blame (mutable) | Controller AID (KEL-anchored) |
| Audit trail | Git history (rewritable) | Append-only chain |
| Tamper detection | None | SAID verification fails |
| Cross-project sync | Manual | SAID reference |

## Install

```bash
pip install keri-sec
```

## Usage

### Define a governed stack

```python
from keri_sec import StackManager, KERI_PRODUCTION_STACK

sm = StackManager()
stack = sm.define_stack(
    name="my-project",
    controller_aid="EController...",
    constraints=KERI_PRODUCTION_STACK,
)
```

### Verify in CI

```python
APPROVED_SAID = os.environ["APPROVED_STACK_SAID"]

verified, _, _ = sm.verify_pyproject(pyproject_content, expected_said=APPROVED_SAID)
if not verified:
    sys.exit("DEPLOY BLOCKED: dependencies don't match approved SAID")
```

### CLI

```bash
keri-sec define my-project --controller EController...
keri-sec check my-project
keri-sec install my-project
keri-sec generate my-project --pyproject
```

## DAID Registries

keri-sec includes governed registries for three artifact types, each using DAID (stable identity across content rotation):

| Registry | Governs | Key property |
|----------|---------|--------------|
| `AlgorithmDAIDRegistry` | Cryptographic algorithms | Category (hash, sig, KDF) |
| `SchemaDAIDRegistry` | ACDC credential schemas | Breaking change tracking |
| `PackageDAIDRegistry` | Python packages | Publisher AID binding |

All three support: register, resolve, rotate, deprecate, revoke.

Cardinal rules (via `keri-governance`) define minimum verification strength per operation — e.g., registration requires TEL-anchored credentials, resolution needs only a SAID.

## Attestation Tiers

Three tiers for graduated trust:

| Tier | Trust | What it proves |
|------|-------|----------------|
| TEL_ANCHORED | Highest | Full credential chain (issuer AID + KEL + TEL) |
| KEL_ANCHORED | Medium | Signature verifiable against key state |
| SAID_ONLY | Integrity | Content hash — no authority claim |

No "signed-only" tier. A signature without KEL anchoring violates KERI's end-to-end verifiability.

## Extension Handlers

Custom constraint types via handler registration:

```python
from keri_sec import ConstraintHandler, register_handler

class DockerImageHandler(ConstraintHandler):
    @property
    def code(self) -> str:
        return "D"

    @property
    def type_name(self) -> str:
        return "docker-image"

    def verify(self, name, spec):
        # Your verification logic
        ...

register_handler("docker-image", DockerImageHandler())
```

Ground types (python, package, system, binary) are built in. Extension types compose on them.

## Dependencies

- `keri>=1.2.0` — Core KERI (KEL, TEL, SAID computation)
- `hio>=0.6.14` — HIO async (Doer lifecycle)
- `keri-governance>=0.1.0` — Constraint algebra and cardinal rules
- `packaging>=23.0` — Version specifier parsing
- libsodium (system)

## License

Apache-2.0
