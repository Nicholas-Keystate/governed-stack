# Transit vs KERI: The Schema Paradox Resolved

**Thesis**: Transit and KERI both reject central schema registries but use different mechanisms to achieve the same goal: **self-describing, locally-verifiable data**.

---

## The Apparent Contradiction

| System | Claim | Reality |
|--------|-------|---------|
| **Transit** | "has no schemas" | Handler code IS the schema |
| **KERI** | "requires schemas" | Schemas are content-addressed, not registry-dependent |

Both reject the same thing: **authoritative schema registries as trust anchors**.

---

## Part 1: What Transit Actually Means

Transit's spec says: "Transit is not a type system, and has no schemas."

But what does this ACTUALLY mean?

### What Transit Rejects

```
Traditional Schema Pattern:
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   Producer   │ ──► │ Schema Registry │ ◄── │   Consumer   │
│              │     │   (Authority)   │     │              │
│ "I produce   │     │ "I define what  │     │ "I must ask  │
│  type Foo"   │     │  Foo means"     │     │  what Foo    │
│              │     │                 │     │   means"     │
└──────────────┘     └─────────────────┘     └──────────────┘
                            ▲
                            │
                     SINGLE POINT OF
                     TRUST / FAILURE
```

### What Transit Does Instead

```
Transit Pattern:
┌──────────────┐                           ┌──────────────┐
│   Producer   │ ────────────────────────► │   Consumer   │
│              │                           │              │
│ Write        │   "~#foo" + value         │ Read         │
│ Handler:     │   (self-describing)       │ Handler:     │
│ Foo → ~#foo  │ ────────────────────────► │ ~#foo → Foo  │
└──────────────┘                           └──────────────┘
       │                                          │
       │                                          │
       ▼                                          ▼
   Handler IS                               Handler IS
   the schema                               the schema
   (code, not data)                         (code, not data)
```

**Key insight**: The handler's `serialize()` and `deserialize()` methods ARE the schema definition. They're just expressed in code rather than JSON Schema.

---

## Part 2: What KERI Actually Does

KERI credentials require a schema SAID in the `s` field:

```python
# From keripy/src/keri/vc/proving.py
vc = {
    "v": "ACDC10JSON000197_",
    "d": "ESAID...",
    "i": "EIssuer...",
    "s": "ESchemaS AID...",  # <-- Schema SAID required
    "a": { ... }
}
```

But the schema is NOT from a central registry:

```python
# From keripy/src/keri/core/scheming.py
class CacheResolver:
    """Sample jsonschema resolver for loading schema $ref
    references from a LOCAL HASH."""

    def resolve(self, uri):
        schemer = self.db.schema.get(uri)  # Local lookup by SAID
        return schemer.raw
```

### What KERI Achieves

```
KERI Pattern:
┌──────────────┐                           ┌──────────────┐
│   Issuer     │ ────────────────────────► │   Verifier   │
│              │                           │              │
│ Credential   │   Credential + Schema     │ Validates    │
│ + Schema     │   (or Schema SAID only)   │ against      │
│ SAID         │ ────────────────────────► │ cached/      │
│              │                           │ fetched      │
└──────────────┘                           │ schema       │
                                           └──────────────┘
       │                                          │
       │                                          │
       ▼                                          ▼
   Schema is                               Schema is
   content-addressed                       verifiable
   (SAID = hash)                           (SAID matches)
```

**Key insight**: The schema SAID IS the "tag" in Transit terms. Change the schema, change the SAID. No central authority decides what the SAID means.

---

## Part 3: The Convergence

Both systems achieve:

| Property | Transit | KERI |
|----------|---------|------|
| **Self-describing** | Tag embedded in data | Schema SAID in credential |
| **No central registry** | Handler knows type | Schema resolved by SAID |
| **Locally verifiable** | Handler validates | Schema validates |
| **Extensible** | Register new handlers | Define new schemas |
| **Forward compatible** | TaggedValue preserves unknown | Unknown schemas can be cached |

### The Core Equivalence

```
Transit:  ~#foo + value    ≡    "I am a Foo, here's my data"
KERI:     s:ESAID + a:{...} ≡    "I conform to schema ESAID, here's my data"
```

Both are saying: **"This data describes itself. You don't need to ask anyone what it means."**

---

## Part 4: The Meaningful Difference

Where they diverge:

| Aspect | Transit | KERI |
|--------|---------|------|
| **Schema location** | In handler code | In JSON Schema document |
| **Validation timing** | Deserialization | Verification |
| **Schema evolution** | Deploy new handler | Publish new schema SAID |
| **Unknown types** | TaggedValue (preserves) | Can cache schema for later |
| **Machine readability** | Handler code only | JSON Schema is queryable |

### The Trade-off

```
Transit:
+ Schema is executable (handler code)
+ No separate artifact to manage
- Schema not introspectable without code
- Schema evolution requires code deployment

KERI:
+ Schema is data (JSON Schema)
+ Queryable, machine-readable
+ Evolvable without code changes
- Requires schema resolution mechanism
- Additional artifact to manage
```

---

## Part 5: Implications for keri-sec

### Current Implementation

keri-sec uses Transit pattern for **ground types**:

```python
class PackageHandler(ConstraintHandler):
    def serialize(self, name: str, spec: str) -> bytes:
        # Handler defines the schema implicitly
        data = {"handler": "K", "type": "package", "name": name, "spec": spec}
        return json.dumps(data, sort_keys=True).encode()

    def verify(self, name: str, spec: str) -> VerificationResult:
        # Handler defines the validation logic
        ...
```

### Hybrid Approach

Extensions could bridge to KERI schemas:

```python
class ExtensionConstraint:
    tag: str
    ground_type: str  # Uses handler (Transit pattern)
    constraints: List[Dict]
    metadata: Dict = {
        # Optional: link to ACDC schema for complex types
        "acdc_schema_said": "ESchemaForComplexConstraint...",
    }
```

### The Insight

**Ground types** (python, package, system, binary):
- Well-known semantics
- Handler IS the schema (Transit pattern)
- No external definition needed

**Extension types** (user-defined composites):
- May need formal definition
- Can link to ACDC schema SAID
- Schema provides introspectable structure

**Stack profiles** (collections of constraints):
- SAID is content-address (KERI pattern)
- Structure defined by code (Transit pattern)
- Hybrid: self-describing but not schema-dependent

---

## Part 6: The Deeper Question

### Could KERI Adopt Transit-Style "Handler as Schema"?

For some use cases, yes:

| Credential Type | Schema Approach | Rationale |
|-----------------|-----------------|-----------|
| **vLEI** | JSON Schema (current) | Formal, queryable, regulatory |
| **Agent capabilities** | Handler (Transit-style) | Internal, well-known semantics |
| **Session credentials** | Handler (Transit-style) | Ephemeral, code-defined |
| **Turn attestations** | Hybrid | Known structure, SAID-addressed |

### The Pattern

```python
# Future: CredentialHandler (Transit-inspired for KERI)
class CredentialHandler(ABC):
    @property
    def acdc_type(self) -> str:
        """ACDC type identifier (like Transit tag)."""

    def serialize(self, data: dict) -> bytes:
        """Canonical serialization for SAID computation."""

    def validate(self, credential: dict) -> ValidationResult:
        """Handler-based validation (no JSON Schema needed)."""

# For well-known internal credentials
class SessionCredentialHandler(CredentialHandler):
    acdc_type = "session"

    def validate(self, cred):
        # Handler knows the structure - no schema lookup
        return cred.get("a", {}).get("session_id") is not None
```

---

## Part 7: Synthesis

### What Transit Got Right

1. **Handler as schema** - Code IS documentation IS validation
2. **No opaque blobs** - Extensions bottom out on ground types
3. **Self-describing** - Type travels with data
4. **Decentralized** - No registry to call

### What KERI Adds

1. **Cryptographic binding** - Schema SAID proves structure
2. **Queryable schemas** - JSON Schema is introspectable
3. **Credential chaining** - Schema edges link credentials
4. **Revocation** - Schema references can be managed

### The Unified Model

```
                    ┌─────────────────────────────────────┐
                    │        Self-Describing Data         │
                    └─────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
                    ▼                                   ▼
          ┌─────────────────┐               ┌─────────────────┐
          │ Transit Pattern │               │  KERI Pattern   │
          │                 │               │                 │
          │ Type in code    │               │ Type in schema  │
          │ Handler IS      │               │ Schema SAID     │
          │ schema          │               │ references def  │
          │                 │               │                 │
          │ Best for:       │               │ Best for:       │
          │ - Internal      │               │ - External      │
          │ - Well-known    │               │ - Formal        │
          │ - Code-bound    │               │ - Queryable     │
          └─────────────────┘               └─────────────────┘
                    │                                   │
                    └─────────────────┬─────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │           Hybrid Pattern            │
                    │                                     │
                    │ Ground types: Handler (Transit)     │
                    │ Extensions: Schema SAID (KERI)      │
                    │ Composites: SAID over handler data  │
                    └─────────────────────────────────────┘
```

---

## Conclusion

**Transit's "no schemas" claim is accurate but misleading.**

Both Transit and KERI reject central schema registries. They just encode type semantics differently:
- Transit: In handler code
- KERI: In content-addressed JSON Schema

**Neither requires calling home to understand data.**

For keri-sec, the hybrid approach is optimal:
- Ground types use handlers (Transit pattern)
- Extensions can link schemas (KERI pattern)
- Stack SAIDs provide content-addressing (both patterns)

The real question isn't "schemas vs no schemas" but **"where does type knowledge live?"**:
- In code that travels with the application (Transit)
- In documents that travel with the data (KERI)
- Both are valid; choose based on use case.

---

## References

- [Transit Format Specification](https://github.com/cognitect/transit-format)
- [ACDC Specification](https://trustoverip.github.io/tswg-acdc-specification/)
- [keripy scheming.py](https://github.com/WebOfTrust/keripy/blob/main/src/keri/core/scheming.py)
- [keripy proving.py](https://github.com/WebOfTrust/keripy/blob/main/src/keri/vc/proving.py)
