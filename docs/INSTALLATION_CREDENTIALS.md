# Installation Credentials: End-to-End Verifiable Environments

> **Principle:** SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.

## Problem

Current keri-sec computes SAIDs but doesn't verify them at runtime.
The SAID in `[tool.keri-sec]` is decoration, not verification.

```
Current Flow (BROKEN):
pyproject.toml → SAID computed → stored → NEVER VERIFIED AGAIN
                                              ↑
                                    This violates KERI principles
```

## Solution: Installation Credentials

Every environment installation produces a TEL-anchored credential that:
1. Records exactly what was installed
2. Is signed by the installing session's AID
3. Can be verified before any code runs

```
Correct Flow:
┌─────────────────────────────────────────────────────────────────┐
│                    INSTALLATION                                  │
├─────────────────────────────────────────────────────────────────┤
│  1. Resolve dependencies → lock file                            │
│  2. Compute lock_said (exact versions)                          │
│  3. Install packages                                            │
│  4. Compute wheel SAIDs for each installed package              │
│  5. Issue InstallationCredential (TEL-anchored)                 │
│  6. Store credential in .governed/installation.json             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFICATION (Every Run)                      │
├─────────────────────────────────────────────────────────────────┤
│  1. Load InstallationCredential                                 │
│  2. Verify TEL status (not revoked)                             │
│  3. Check installed packages match credential                   │
│  4. FAIL if mismatch - environment tampered                     │
└─────────────────────────────────────────────────────────────────┘
```

## Schema: InstallationCredential

```json
{
  "$id": "EInstallationCredentialSchema...",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Installation Credential",
  "description": "Attestation of installed packages in a governed environment",
  "type": "object",
  "credentialType": "InstallationCredential",
  "version": "1.0.0",
  "properties": {
    "v": {"type": "string", "description": "ACDC version"},
    "d": {"type": "string", "description": "Credential SAID"},
    "i": {"type": "string", "description": "Issuer AID (installer)"},
    "ri": {"type": "string", "description": "Registry identifier"},
    "s": {"type": "string", "description": "Schema SAID"},
    "a": {
      "type": "object",
      "properties": {
        "d": {"type": "string", "description": "Attributes SAID"},
        "dt": {"type": "string", "format": "date-time"},
        "stack_said": {"type": "string", "description": "Governing stack SAID"},
        "lock_said": {"type": "string", "description": "Resolved lock file SAID"},
        "python_version": {"type": "string"},
        "platform": {"type": "string"},
        "venv_path": {"type": "string"},
        "packages": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": {"type": "string"},
              "version": {"type": "string"},
              "wheel_said": {"type": "string", "description": "SAID of wheel file"}
            }
          }
        }
      }
    }
  }
}
```

## Schema: SAIDified Lock File

```json
{
  "d": "ELockFileSAID...",
  "v": "GS10JSON000000_",
  "governed_by": "EStackSAID...",
  "resolved_at": "2026-01-26T16:50:00Z",
  "resolver": "uv-0.5.0",
  "python": {
    "version": "3.12.12",
    "platform": "darwin-arm64"
  },
  "packages": [
    {
      "name": "hio",
      "version": "0.6.19",
      "wheel": "hio-0.6.19-py3-none-any.whl",
      "wheel_said": "EWheelSAID...",
      "source": "pypi"
    },
    {
      "name": "keri",
      "version": "1.2.0",
      "wheel": "keri-1.2.0-py3-none-any.whl",
      "wheel_said": "EWheelSAID...",
      "source": "pypi"
    }
  ]
}
```

## Implementation Architecture

### Handler Pattern (Modular Package Managers)

```
keri_sec/
├── handlers/
│   ├── base.py              # PackageManagerHandler ABC
│   ├── uv.py                # UVHandler - primary
│   ├── pip.py               # PipHandler - fallback
│   └── registry.py          # Handler registry
├── credentials/
│   ├── schemas/
│   │   ├── installation.json
│   │   └── lock_file.json
│   ├── installation.py      # InstallationCredential issuance
│   └── lock_file.py         # SAIDified lock file generation
├── verification/
│   ├── environment.py       # Verify installed matches credential
│   ├── hooks.py             # pytest/pre-run hooks
│   └── cli.py               # `keri-sec verify` command
└── doers/
    ├── resolver.py          # ResolutionDoer - HIO pattern
    ├── installer.py         # InstallerDoer
    └── verifier.py          # VerifierDoer
```

### PackageManagerHandler ABC

```python
from abc import ABC, abstractmethod
from typing import List, Tuple
from dataclasses import dataclass

@dataclass
class ResolvedPackage:
    name: str
    version: str
    wheel_url: str
    wheel_said: str  # SAID of wheel content

@dataclass
class ResolutionResult:
    success: bool
    lock_said: str
    packages: List[ResolvedPackage]
    python_version: str
    error: str = ""

class PackageManagerHandler(ABC):
    """Abstract handler for package manager operations."""

    @property
    @abstractmethod
    def code(self) -> str:
        """Single-char handler code (U=uv, P=pip, C=conda)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name."""

    @abstractmethod
    def resolve(self, constraints: dict, python_version: str) -> ResolutionResult:
        """Resolve constraints to exact versions."""

    @abstractmethod
    def install(self, packages: List[ResolvedPackage], venv_path: str) -> bool:
        """Install resolved packages to venv."""

    @abstractmethod
    def get_installed(self, venv_path: str) -> List[Tuple[str, str]]:
        """Get list of (name, version) installed in venv."""

    @abstractmethod
    def compute_wheel_said(self, wheel_path: str) -> str:
        """Compute SAID of wheel file content."""
```

### UVHandler Implementation

```python
class UVHandler(PackageManagerHandler):
    """UV package manager handler."""

    @property
    def code(self) -> str:
        return "U"

    @property
    def name(self) -> str:
        return "uv"

    def resolve(self, constraints: dict, python_version: str) -> ResolutionResult:
        """Use uv pip compile to resolve."""
        import subprocess
        import tempfile

        # Write constraints to temp requirements.in
        with tempfile.NamedTemporaryFile(mode='w', suffix='.in', delete=False) as f:
            for pkg, spec in constraints.items():
                if pkg != "python":
                    f.write(f"{pkg}{spec}\n")
            req_in = f.name

        # Run uv pip compile
        result = subprocess.run(
            ["uv", "pip", "compile", req_in, "--python-version", python_version],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            return ResolutionResult(
                success=False,
                lock_said="",
                packages=[],
                python_version=python_version,
                error=result.stderr
            )

        # Parse output, compute SAIDs
        packages = self._parse_resolution(result.stdout)
        lock_said = self._compute_lock_said(packages, python_version)

        return ResolutionResult(
            success=True,
            lock_said=lock_said,
            packages=packages,
            python_version=python_version
        )

    def _compute_lock_said(self, packages: List[ResolvedPackage], python_version: str) -> str:
        """Compute SAID of lock file content."""
        from keri.core.coring import Saider
        import json

        lock_data = {
            "python": python_version,
            "packages": [
                {"name": p.name, "version": p.version, "wheel_said": p.wheel_said}
                for p in sorted(packages, key=lambda p: p.name)
            ]
        }

        raw = json.dumps(lock_data, sort_keys=True, separators=(",", ":")).encode()
        saider = Saider(sad={"d": ""}, code=coring.MtrDex.Blake3_256, label="d")
        return saider.qb64
```

## CLI Commands

```bash
# Install with credential issuance
keri-sec install my-stack --venv --credential
# Creates: .governed/installation.json (TEL-anchored)

# Verify environment before running
keri-sec verify
# Checks: installed packages match credential, TEL not revoked

# Show installation credential
keri-sec credential show
# Displays: credential details, TEL status, package list

# Revoke installation (e.g., after security issue found)
keri-sec credential revoke --reason "CVE-2026-1234 in requests"
```

## Pytest Integration

```python
# conftest.py
import pytest
from keri_sec.verification import verify_environment

def pytest_configure(config):
    """Verify environment before running tests."""
    result = verify_environment()
    if not result.verified:
        pytest.exit(
            f"Environment verification failed: {result.error}\n"
            f"Run: keri-sec install --credential"
        )
```

## CI/CD Integration

```yaml
# .github/workflows/test.yml
jobs:
  test:
    steps:
      - uses: actions/checkout@v4

      - name: Install governed environment
        run: |
          keri-sec install ${{ secrets.STACK_SAID }} --venv --credential

      - name: Verify environment
        run: keri-sec verify

      - name: Run tests
        run: .venv/bin/pytest
```

## Migration Path

1. **Phase 1: Lock File SAIDs** (Non-breaking)
   - Add `keri-sec lock` command
   - Generate SAIDified lock files alongside installation
   - No behavioral change to existing `install`

2. **Phase 2: Installation Credentials** (Opt-in)
   - Add `--credential` flag to `install`
   - Issue TEL-anchored credential when flag present
   - Add `verify` command

3. **Phase 3: Verification by Default** (Breaking)
   - Make `--credential` the default
   - Add `--no-credential` for legacy behavior
   - pytest hook enabled by default

## Security Model

### What Installation Credentials Prove

1. **WHO installed:** Installer's AID (traceable via KEL)
2. **WHAT was installed:** Exact packages with wheel SAIDs
3. **WHEN installed:** Timestamp in credential
4. **GOVERNED BY:** Link to stack SAID (authorization chain)
5. **NOT REVOKED:** TEL status check at verification time

### Attack Scenarios Prevented

| Attack | Without Credentials | With Credentials |
|--------|---------------------|------------------|
| Package swap | Undetected | Wheel SAID mismatch |
| Version downgrade | Undetected | Version mismatch |
| Env tampering | Undetected | Credential verification fails |
| Unauthorized install | Git blame only | AID not in authorized list |
| Post-install modification | Undetected | Package list mismatch |

## Related Work

- **SLSA (Supply-chain Levels for Software Artifacts):** Focuses on build provenance
- **Sigstore:** Keyless signing for artifacts
- **in-toto:** Software supply chain layout verification

**Key Differentiator:** KERI-native. No central authorities. Self-certifying identifiers.
Installation credentials are just another ACDC in the KERI ecosystem.
