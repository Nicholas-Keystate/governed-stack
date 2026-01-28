# CESR + Transit: Encoding vs Validation

**Question**: Should Transit be a CESR encoding for internal work?

**Answer**: Transit patterns are a validation strategy, not an encoding. But CESR COULD carry a marker indicating which validation strategy to use.

---

## The Current CESR Landscape

CESR payload types indicate semantic meaning:

| Code | Meaning | Validation |
|------|---------|------------|
| `Xicp` | Inception event | KEL rules |
| `Xrot` | Rotation event | KEL rules |
| `XRFI` | RFI message | Protocol rules |
| `XHOP` | Hop message | Routing rules |

These are **semantic markers within CESR encoding**.

---

## The Proposal: Validation Strategy Markers

What if CESR indicated validation strategy?

### Option A: New Payload Types for Handler-Validated Credentials

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Proposed Payload Types                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Xint  - Internal credential (handler-validated)                   │
│   │                                                                 │
│   ├── Xses - Session credential (SessionCredentialHandler)          │
│   ├── Xtrn - Turn credential (TurnCredentialHandler)                │
│   ├── Xcap - Capability credential (CapabilityCredentialHandler)    │
│   └── Xtsk - Task credential (TaskCredentialHandler)                │
│                                                                     │
│   Xext  - External credential (schema-validated)                    │
│   │                                                                 │
│   └── Uses standard ACDC with schema SAID resolution                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Option B: Validation Hint in ACDC Structure

```python
# Add validation hint to ACDC attributes
credential = {
    "v": "ACDC10JSON000197_",
    "d": "ESAID...",
    "i": "EIssuer...",
    "s": "ESchema...",
    "a": {
        "d": "EAttrs...",
        "v": "handler:session",  # Validation hint
        # ... actual attributes
    }
}
```

### Option C: Handler Registry with SAID Mapping

```python
# Handlers declare their schema SAID (computed from handler definition)
class SessionCredentialHandler(CredentialHandler):
    @property
    def schema_said(self) -> str:
        # SAID of handler's implicit schema
        return "EHandlerSchemaSAID..."

# Validation dispatch
def validate(credential):
    schema_said = credential["s"]

    # Check if we have a handler for this schema
    handler = HANDLER_BY_SCHEMA.get(schema_said)

    if handler:
        # Fast path: handler-based validation
        return handler.validate(credential)
    else:
        # Slow path: fetch schema, JSON Schema validation
        return schema_validate(credential)
```

---

## Analysis: Which Approach?

### Option A (New Payload Types)

**Pros:**
- Clear at CESR level: "This is internal"
- Parser knows validation strategy before parsing attributes
- Aligns with existing payload type patterns

**Cons:**
- Proliferates payload types
- Internal/external is application-level, not protocol-level
- May not need CESR-level distinction

### Option B (Validation Hint)

**Pros:**
- No CESR changes needed
- Flexible per-credential
- Backwards compatible

**Cons:**
- Hint could be ignored
- Not self-framing at CESR level
- Adds attribute noise

### Option C (Handler Registry)

**Pros:**
- Schema SAID is already there
- Handlers registered by schema SAID
- Automatic dispatch based on existing field

**Cons:**
- Requires handler-to-schema mapping
- Schema SAID collision risk
- Implicit rather than explicit

---

## Recommendation: Option C with Convention

The cleanest approach is:

1. **Handlers compute their schema SAID** from their implicit schema
2. **Credentials reference this SAID** in the `s` field (standard ACDC)
3. **Validators check handler registry first** before schema lookup
4. **Convention**: Handler SAIDs use a reserved prefix or pattern

```python
# Convention: Handler-based schemas use "EH" prefix (Handler)
# vs "ES" for standard schemas

HANDLER_SCHEMA_PREFIX = "EH"

class SessionCredentialHandler(CredentialHandler):
    @property
    def schema_said(self) -> str:
        # Computed from handler definition
        # Starts with "EH" by convention
        return "EHSessionHandler_computed_said..."

def validate(credential):
    schema_said = credential["s"]

    if schema_said.startswith("EH"):
        # Handler-based validation expected
        handler = get_handler_by_schema(schema_said)
        if handler:
            return handler.validate(credential)
        else:
            raise ValueError(f"No handler for {schema_said}")
    else:
        # Schema-based validation
        return schema_validate(credential)
```

---

## The Deeper Question

**Is "internal vs external" the right distinction?**

Maybe not. Consider:

| Distinction | Better Framing |
|-------------|----------------|
| Internal vs External | **Where does type knowledge live?** |
| Handler vs Schema | **Code vs Document** |
| Fast vs Slow | **Local vs Remote resolution** |

The real question is: **Can the validator understand this credential without external lookup?**

- **Yes** → Handler-based (Transit pattern)
- **No** → Schema-based (KERI pattern)

This isn't about "internal" credentials - it's about **colocation of code and data**.

---

## CESR's Role

CESR doesn't need to encode validation strategy because:

1. **CESR is about framing** - "How many bytes? What type?"
2. **Validation is about semantics** - "Does this mean what it claims?"
3. **Schema SAID already indicates type** - Handler or schema can both be looked up by SAID

The magic is that **handler and schema can share the same SAID** if the handler generates a schema that matches its validation logic.

---

## Practical Implementation

For keri-sec and ai-orchestrator:

```python
# 1. Handler computes schema-equivalent SAID
class SessionCredentialHandler(CredentialHandler):
    def __init__(self):
        # Generate JSON Schema from handler
        self._schema = self._generate_schema()
        self._schema_said = compute_said(self._schema)

    @property
    def schema_said(self):
        return self._schema_said

    def _generate_schema(self):
        # Handler definition → JSON Schema
        return {
            "$id": f"urn:handler:{self.acdc_type}",
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "session_id": {"type": "string"},
                # ... from handler knowledge
            }
        }

# 2. Validator uses handler when available
def validate_credential(credential):
    schema_said = credential["s"]

    # Try handler first (fast path)
    handler = get_handler_by_schema_said(schema_said)
    if handler:
        return handler.validate(credential)

    # Fall back to schema (slow path)
    schema = fetch_schema(schema_said)
    return jsonschema.validate(credential, schema)

# 3. Issuer uses handler to create credential
def issue_session_credential(session_id, issuer_aid):
    handler = SessionCredentialHandler()

    return {
        "v": "ACDC10JSON000197_",
        "d": "",  # Computed
        "i": issuer_aid,
        "s": handler.schema_said,  # Handler's schema SAID
        "a": {
            "session_id": session_id,
        }
    }
```

---

## Conclusion

**Transit is not a CESR encoding - it's a validation pattern.**

But CESR and Transit can work together:
- CESR provides the wire format (always)
- Schema SAID identifies the type (standard ACDC)
- Handlers can be registered against schema SAIDs
- Validation dispatches based on handler availability

The "internal vs external" distinction maps to:
- **Handler available** → Fast, local validation
- **Handler unavailable** → Schema lookup, JSON Schema validation

No new CESR codes needed. Just a handler registry indexed by schema SAID.
