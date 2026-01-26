#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Governed Stack CLI

Cryptographic dependency governance with KERI SAIDs.

Commands:
    governed-stack init [--controller <aid>]     Initialize from pyproject.toml
    governed-stack check [<said>]                Check compliance
    governed-stack diff <path>                   Compare with another project
    governed-stack sync                          Update pyproject.toml governance
    governed-stack define <name> --controller <aid> [--stack <preset>]
    governed-stack install <said> [--uv|--pip]
    governed-stack generate <said> [--pyproject|--requirements]
    governed-stack list
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from governed_stack import (
    StackManager,
    get_stack_manager,
    KERI_PRODUCTION_STACK,
    KERI_DEV_STACK,
    KGQL_STACK,
    AI_ORCHESTRATOR_STACK,
    WITNESS_STACK,
    MINIMAL_STACK,
)


PRESET_STACKS = {
    "keri": KERI_PRODUCTION_STACK,
    "keri-dev": KERI_DEV_STACK,
    "kgql": KGQL_STACK,
    "ai-orchestrator": AI_ORCHESTRATOR_STACK,
    "witness": WITNESS_STACK,
    "minimal": MINIMAL_STACK,
}


def parse_pyproject(path: Path) -> Tuple[Optional[str], Dict[str, str], Dict[str, str]]:
    """
    Parse pyproject.toml and extract dependencies.

    Returns:
        (project_name, constraints, existing_governance)
    """
    if not path.exists():
        return None, {}, {}

    content = path.read_text()
    constraints = {}
    governance = {}
    project_name = None

    # Simple TOML parsing (handles common cases)
    in_dependencies = False
    in_governance = False

    for line in content.split("\n"):
        line = line.strip()

        # Project name
        if line.startswith("name"):
            match = re.search(r'name\s*=\s*"([^"]+)"', line)
            if match:
                project_name = match.group(1)

        # Python version
        if "requires-python" in line:
            match = re.search(r'requires-python\s*=\s*"([^"]+)"', line)
            if match:
                constraints["python"] = match.group(1)

        # Dependencies section
        if line == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies:
            if line == "]":
                in_dependencies = False
                continue
            # Parse: "package>=version",
            match = re.search(r'"([^"]+)"', line)
            if match:
                dep = match.group(1)
                for op in [">=", "<=", "==", ">", "<", "~=", "!="]:
                    if op in dep:
                        name, version = dep.split(op, 1)
                        # Handle extras: package[extra]>=version
                        name = name.split("[")[0]
                        constraints[name.strip()] = f"{op}{version.strip()}"
                        break

        # Governance section
        if line == "[tool.governed-stack]":
            in_governance = True
            continue
        if in_governance:
            if line.startswith("["):
                in_governance = False
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                governance[key] = value

    return project_name, constraints, governance


def cmd_init(args):
    """Initialize governance from existing pyproject.toml."""
    pyproject = Path(args.path) / "pyproject.toml" if args.path else Path("pyproject.toml")

    if not pyproject.exists():
        print(f"No pyproject.toml found at {pyproject}", file=sys.stderr)
        print("\nCreate one first, then run: governed-stack init")
        return 1

    project_name, constraints, existing = parse_pyproject(pyproject)

    if existing.get("stack_said"):
        print(f"Project already governed!")
        print(f"  Stack SAID: {existing['stack_said']}")
        print(f"  Owner: {existing.get('owner_baid', 'unknown')}")
        print("\nTo update, use: governed-stack sync")
        return 0

    if not constraints:
        print("No dependencies found in pyproject.toml")
        return 1

    # Use provided controller or generate placeholder
    controller = args.controller or f"BAID_{(project_name or 'PROJECT').upper().replace('-', '_')}"
    name = project_name or pyproject.parent.name

    sm = get_stack_manager()
    stack = sm.define_stack(
        name=f"{name}-production",
        controller_aid=controller,
        constraints=constraints,
        rationale=f"Initialized from {pyproject}",
    )

    print(f"Initialized governance for: {name}")
    print(f"  Stack SAID: {stack.said}")
    print(f"  Controller: {controller}")
    print(f"  Constraints: {len(stack.constraints)}")
    print()

    for pkg, c in sorted(stack.constraints.items()):
        print(f"    {pkg}: {c.version_spec}")

    print()
    print("Next steps:")
    print("  1. Run: governed-stack sync    # Add governance to pyproject.toml")
    print("  2. Run: governed-stack check   # Verify compliance")

    return 0


def cmd_diff(args):
    """Compare current project with another for version conflicts."""
    current_pyproject = Path("pyproject.toml")
    other_path = Path(args.path)

    # Handle if path is a directory
    if other_path.is_dir():
        other_pyproject = other_path / "pyproject.toml"
    else:
        other_pyproject = other_path

    if not current_pyproject.exists():
        print("No pyproject.toml in current directory", file=sys.stderr)
        return 1

    if not other_pyproject.exists():
        print(f"No pyproject.toml found at {other_pyproject}", file=sys.stderr)
        return 1

    current_name, current_constraints, _ = parse_pyproject(current_pyproject)
    other_name, other_constraints, _ = parse_pyproject(other_pyproject)

    current_name = current_name or "current"
    other_name = other_name or other_path.parent.name

    # Find shared packages
    shared = set(current_constraints.keys()) & set(other_constraints.keys())
    only_current = set(current_constraints.keys()) - set(other_constraints.keys())
    only_other = set(other_constraints.keys()) - set(current_constraints.keys())

    # Find conflicts
    conflicts = []
    aligned = []
    for pkg in sorted(shared):
        current_spec = current_constraints[pkg]
        other_spec = other_constraints[pkg]
        if current_spec != other_spec:
            conflicts.append((pkg, current_spec, other_spec))
        else:
            aligned.append(pkg)

    print(f"Comparing: {current_name} ↔ {other_name}")
    print("=" * 50)
    print()

    if conflicts:
        print(f"⚠ Version Conflicts ({len(conflicts)}):")
        for pkg, curr, other in conflicts:
            print(f"  {pkg}:")
            print(f"    {current_name}: {curr}")
            print(f"    {other_name}: {other}")
        print()

    if aligned:
        print(f"✓ Aligned ({len(aligned)}): {', '.join(aligned)}")
        print()

    if only_current:
        print(f"Only in {current_name} ({len(only_current)}): {', '.join(sorted(only_current))}")
    if only_other:
        print(f"Only in {other_name} ({len(only_other)}): {', '.join(sorted(only_other))}")

    if not conflicts:
        print("\n✓ No version conflicts detected")
        return 0

    return 1 if conflicts else 0


def resolve_version_conflicts(constraints_by_project: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """
    Resolve version conflicts by taking the strictest constraint.

    For >=X.Y, take the highest minimum.
    For <=X.Y, take the lowest maximum.
    For ==X.Y, conflict if different.
    """
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

    unified = {}

    # Collect all versions for each package
    package_specs: Dict[str, List[Tuple[str, str]]] = {}  # pkg -> [(project, spec), ...]
    for project, constraints in constraints_by_project.items():
        for pkg, spec in constraints.items():
            if pkg not in package_specs:
                package_specs[pkg] = []
            package_specs[pkg].append((project, spec))

    for pkg, specs in package_specs.items():
        if len(specs) == 1:
            unified[pkg] = specs[0][1]
            continue

        # Find strictest constraint
        min_versions = []
        for project, spec in specs:
            # Extract version from spec like ">=3.12" or ">=1.2.0"
            for op in [">=", ">", "=="]:
                if spec.startswith(op):
                    try:
                        ver = Version(spec[len(op):])
                        min_versions.append((ver, op, spec))
                    except:
                        pass
                    break

        if min_versions:
            # Take highest minimum version
            strictest = max(min_versions, key=lambda x: x[0])
            unified[pkg] = strictest[2]
        else:
            # Fallback to first spec
            unified[pkg] = specs[0][1]

    return unified


def cmd_workspace(args):
    """Govern all projects in a workspace directory."""
    workspace = Path(args.path) if args.path else Path(".")

    if not workspace.is_dir():
        print(f"Not a directory: {workspace}", file=sys.stderr)
        return 1

    # Find all projects with pyproject.toml
    projects = {}
    for pyproject in workspace.glob("*/pyproject.toml"):
        project_name, constraints, governance = parse_pyproject(pyproject)
        if constraints:
            projects[pyproject.parent.name] = {
                "path": pyproject,
                "name": project_name or pyproject.parent.name,
                "constraints": constraints,
                "governance": governance,
            }

    if not projects:
        print(f"No projects found in {workspace}")
        return 1

    print(f"Found {len(projects)} projects in workspace")
    print("=" * 50)

    # Collect all constraints
    constraints_by_project = {name: p["constraints"] for name, p in projects.items()}

    # Find conflicts
    all_packages = set()
    for constraints in constraints_by_project.values():
        all_packages.update(constraints.keys())

    conflicts = []
    for pkg in sorted(all_packages):
        specs = [(name, c.get(pkg)) for name, c in constraints_by_project.items() if pkg in c]
        if len(specs) > 1:
            unique_specs = set(s[1] for s in specs)
            if len(unique_specs) > 1:
                conflicts.append((pkg, specs))

    if conflicts:
        print(f"\n⚠ Found {len(conflicts)} version conflicts:")
        for pkg, specs in conflicts:
            print(f"  {pkg}:")
            for project, spec in specs:
                print(f"    {project}: {spec}")

    # Resolve conflicts
    if args.resolve or args.sync:
        print("\nResolving conflicts (taking strictest constraint)...")
        unified = resolve_version_conflicts(constraints_by_project)

        # Show what changed
        changes = []
        for pkg, specs in conflicts:
            new_spec = unified.get(pkg)
            if new_spec:
                for project, old_spec in specs:
                    if old_spec != new_spec:
                        changes.append((project, pkg, old_spec, new_spec))

        if changes:
            print("\nChanges to apply:")
            for project, pkg, old, new in changes:
                print(f"  {project}: {pkg} {old} → {new}")
        else:
            print("\nNo changes needed")

        if args.sync:
            # Apply changes to all projects
            controller = args.controller or "BAID_WORKSPACE"
            sm = get_stack_manager()

            # Define unified workspace stack
            workspace_stack = sm.define_stack(
                name=f"{workspace.name}-workspace",
                controller_aid=controller,
                constraints=unified,
                rationale="Unified workspace governance",
            )

            print(f"\nWorkspace Stack: {workspace_stack.said}")

            # Update each project
            for name, proj in projects.items():
                pyproject = proj["path"]
                project_constraints = proj["constraints"].copy()

                # Update to unified versions
                for pkg in project_constraints:
                    if pkg in unified:
                        project_constraints[pkg] = unified[pkg]

                # Define project stack
                project_stack = sm.define_stack(
                    name=f"{proj['name']}-production",
                    controller_aid=controller,
                    constraints=project_constraints,
                )

                # Read current content
                content = pyproject.read_text()
                lines = content.split("\n")
                new_lines = []
                in_dependencies = False
                skip_governance = False

                for line in lines:
                    # Update dependency versions
                    if line.strip() == "dependencies = [":
                        in_dependencies = True
                        new_lines.append(line)
                        continue

                    if in_dependencies:
                        if line.strip() == "]":
                            in_dependencies = False
                            new_lines.append(line)
                            continue

                        # Check if this line has a package we need to update
                        for pkg, new_spec in unified.items():
                            if pkg != "python" and f'"{pkg}' in line:
                                # Replace the spec
                                match = re.search(r'"([^"]+)"', line)
                                if match:
                                    old_dep = match.group(1)
                                    new_dep = f"{pkg}{new_spec}"
                                    line = line.replace(f'"{old_dep}"', f'"{new_dep}"')
                                break
                        new_lines.append(line)
                        continue

                    # Update requires-python
                    if "requires-python" in line and "python" in unified:
                        line = f'requires-python = "{unified["python"]}"'

                    # Skip old governance section
                    if line.strip() == "[tool.governed-stack]":
                        skip_governance = True
                        continue
                    if skip_governance:
                        if line.strip().startswith("["):
                            skip_governance = False
                        else:
                            continue

                    new_lines.append(line)

                # Remove trailing empty lines
                while new_lines and not new_lines[-1].strip():
                    new_lines.pop()

                # Add governance section
                governance_section = f"""
[tool.governed-stack]
stack_said = "{project_stack.said}"
owner_baid = "{controller}"
workspace_said = "{workspace_stack.said}"
"""
                new_content = "\n".join(new_lines) + "\n" + governance_section
                pyproject.write_text(new_content)
                print(f"  Updated: {name} ({project_stack.said[:20]}...)")

            print(f"\n✓ Synced {len(projects)} projects to workspace governance")

            # TEL anchoring if requested
            if args.tel:
                print("\nIssuing TEL-anchored credentials...")
                try:
                    from governed_stack import tel_available, get_issuer_from_session

                    if not tel_available():
                        print("  ⚠ TEL anchoring not available (missing KERI dependencies)")
                    else:
                        issuer = get_issuer_from_session()
                        if not issuer:
                            print("  ⚠ No KERI session found. Start ai-orchestrator or configure KERI.")
                        else:
                            can, reason = issuer.can_issue()
                            if not can:
                                print(f"  ⚠ Cannot issue: {reason}")
                            else:
                                # Issue workspace credential
                                result = issuer.issue_workspace_credential(
                                    workspace_name=f"{workspace.name}-workspace",
                                    workspace_said=workspace_stack.said,
                                    unified_constraints=unified,
                                    project_saids=[p.said for p in [sm.get_stack_by_name(f"{proj['name']}-production") for proj in projects.values()] if p],
                                )
                                if result.success:
                                    print(f"  ✓ Workspace credential: {result.credential_said}")
                                    print(f"    Registry: {result.registry_said}")
                                else:
                                    print(f"  ⚠ Failed: {result.error}")
                except Exception as e:
                    print(f"  ⚠ TEL error: {e}")

    else:
        if conflicts:
            print("\nRun with --resolve to see unified constraints")
            print("Run with --sync to apply unified constraints to all projects")
            print("Run with --sync --tel to also issue TEL-anchored credentials")

    return 0


def cmd_sync(args):
    """Update pyproject.toml with governance metadata."""
    pyproject = Path(args.path) / "pyproject.toml" if args.path else Path("pyproject.toml")

    if not pyproject.exists():
        print(f"No pyproject.toml found at {pyproject}", file=sys.stderr)
        return 1

    project_name, constraints, existing = parse_pyproject(pyproject)

    if not constraints:
        print("No dependencies found in pyproject.toml")
        return 1

    # Get or create stack
    sm = get_stack_manager()
    controller = existing.get("owner_baid") or args.controller or f"BAID_{(project_name or 'PROJECT').upper().replace('-', '_')}"
    name = project_name or pyproject.parent.name

    stack = sm.define_stack(
        name=f"{name}-production",
        controller_aid=controller,
        constraints=constraints,
    )

    # Read current content
    content = pyproject.read_text()

    # Remove existing [tool.governed-stack] section if present
    lines = content.split("\n")
    new_lines = []
    skip_section = False

    for line in lines:
        if line.strip() == "[tool.governed-stack]":
            skip_section = True
            continue
        if skip_section and line.strip().startswith("["):
            skip_section = False
        if not skip_section:
            new_lines.append(line)

    # Remove trailing empty lines
    while new_lines and not new_lines[-1].strip():
        new_lines.pop()

    # Add governance section
    governance_section = f"""
[tool.governed-stack]
stack_said = "{stack.said}"
owner_baid = "{controller}"
"""

    new_content = "\n".join(new_lines) + "\n" + governance_section

    # Write back
    pyproject.write_text(new_content)

    print(f"Updated {pyproject}")
    print(f"  Stack SAID: {stack.said}")
    print(f"  Owner: {controller}")
    print(f"  Constraints: {len(stack.constraints)}")

    return 0


def cmd_define(args):
    """Define a new governed stack."""
    sm = get_stack_manager()

    # Get constraints from preset or JSON file
    if args.stack:
        if args.stack in PRESET_STACKS:
            constraints = PRESET_STACKS[args.stack]
        else:
            # Try as JSON file
            try:
                constraints = json.loads(Path(args.stack).read_text())
            except Exception as e:
                print(f"Error loading constraints: {e}", file=sys.stderr)
                return 1
    else:
        constraints = MINIMAL_STACK

    stack = sm.define_stack(
        name=args.name,
        controller_aid=args.controller,
        constraints=constraints,
        rationale=args.rationale or "",
    )

    print(f"Defined stack: {stack.name}")
    print(f"  SAID: {stack.said}")
    print(f"  Controller: {stack.controller_aid}")
    print(f"  Constraints: {len(stack.constraints)}")

    for name, c in sorted(stack.constraints.items()):
        print(f"    {name}: {c.version_spec}")

    return 0


def cmd_check(args):
    """Check compliance with a stack."""
    sm = get_stack_manager()

    # If no SAID provided, try current project's governance
    if not args.said:
        pyproject = Path("pyproject.toml")
        if pyproject.exists():
            _, _, governance = parse_pyproject(pyproject)
            if governance.get("stack_said"):
                args.said = governance["stack_said"]
            else:
                print("No stack_said in pyproject.toml. Run: governed-stack init", file=sys.stderr)
                return 1
        else:
            print("No pyproject.toml found. Specify a stack SAID or name.", file=sys.stderr)
            return 1

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    result = sm.check_compliance(stack.said)

    print(f"Stack: {stack.name}")
    print(f"SAID: {stack.said}")
    print(f"Compliant: {'Yes' if result.compliant else 'No'}")
    print()

    for name, check in sorted(result.checks.items()):
        status = "✓" if check.compliant else "✗"
        installed = check.installed or "NOT INSTALLED"
        print(f"  [{status}] {name}: {installed} (requires {check.required})")
        if check.error:
            print(f"       Error: {check.error}")

    if result.missing:
        print(f"\nMissing: {', '.join(result.missing)}")
    if result.outdated:
        print(f"Outdated: {', '.join(result.outdated)}")

    return 0 if result.compliant else 1


def cmd_install(args):
    """Install stack dependencies."""
    sm = get_stack_manager()

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    print(f"Installing stack: {stack.name} ({stack.said[:20]}...)")

    # Determine venv path
    venv_path = None
    if args.venv:
        if args.venv is True:
            # Default venv path
            venv_path = Path(".venv")
        else:
            venv_path = Path(args.venv)
        print(f"Creating venv at: {venv_path}")

    if args.pip:
        if venv_path:
            print("Warning: --venv only works with UV, ignoring", file=sys.stderr)
        success, output = sm.install_with_pip(stack.said, upgrade=args.upgrade)
    else:
        success, output = sm.install_with_uv(
            stack.said,
            upgrade=args.upgrade,
            venv_path=venv_path,
        )

    if success:
        print("Installation successful!")
        if output:
            print(output)

        # ALWAYS issue installation credential - no exceptions
        # Principle: SIGN EVERYTHING. VERIFY EVERYTHING.
        from governed_stack.installation_credential import issue_installation_credential

        # Determine actual venv path for credential
        cred_venv = venv_path or Path(".venv")
        if not cred_venv.exists():
            # Fall back to system Python path detection
            cred_venv = Path(sys.prefix)

        # Credential output path
        cred_path = Path(args.credential_path) if args.credential_path else None

        print(f"\nIssuing installation credential...")

        # Warn about deprecated issuer flag
        issuer_aid = getattr(args, 'issuer', None)
        if issuer_aid:
            print("  WARNING: --issuer is deprecated. Credential will NOT be TEL-anchored.", file=sys.stderr)
            print("  Set up KERI infrastructure for verifiable credentials.", file=sys.stderr)

        try:
            cred, lock_file = issue_installation_credential(
                stack_said=stack.said,
                venv_path=cred_venv,
                output_path=cred_path,
                issuer_aid=issuer_aid,
            )
            print(f"  Lock file SAID: {lock_file.said}")
            print(f"  Credential SAID: {cred.said}")
            print(f"  TEL-anchored: {cred.tel_anchored}")
            print(f"  Packages attested: {len(lock_file.packages)}")
            cred_output = cred_path or Path(".governed/installation.json")
            print(f"  Saved to: {cred_output}")
        except Exception as e:
            # Credential issuance failure IS installation failure
            print(f"FATAL: Credential issuance failed: {e}", file=sys.stderr)
            print("Installation cannot complete without attestation.", file=sys.stderr)
            return 1
    else:
        print(f"Installation failed:\n{output}", file=sys.stderr)

    return 0 if success else 1


def cmd_generate(args):
    """Generate pyproject.toml or requirements.txt."""
    sm = get_stack_manager()

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    if args.requirements:
        output = sm.generate_requirements(stack.said)
    else:
        output = sm.generate_pyproject(stack.said)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Written to {args.output}")
    else:
        print(output)

    return 0


def cmd_list(args):
    """List all defined stacks."""
    sm = get_stack_manager()
    stacks = sm.list_stacks()

    if not stacks:
        print("No stacks defined.")
        print("\nDefine a stack with:")
        print("  governed-stack define my-project --controller <AID> --stack keri")
        return 0

    print(f"Defined stacks ({len(stacks)}):\n")
    for stack in sorted(stacks, key=lambda s: s.name):
        print(f"  {stack.name}")
        print(f"    SAID: {stack.said[:30]}...")
        print(f"    Controller: {stack.controller_aid[:30]}...")
        print(f"    Constraints: {len(stack.constraints)}")
        print()

    return 0


def cmd_verify(args):
    """Verify installed environment matches credential."""
    from pathlib import Path
    from governed_stack.verification import verify_environment

    credential_path = Path(args.credential) if args.credential else None
    venv_path = Path(args.venv) if args.venv else None

    # Always strict. Extra packages are a supply chain attack vector.
    result = verify_environment(
        credential_path=credential_path,
        venv_path=venv_path,
        strict=True,
    )

    # Print results
    print(f"Environment Verification")
    print("=" * 50)
    print(f"Credential SAID: {result.credential_said or '(none)'}")
    print(f"Stack SAID: {result.stack_said or '(none)'}")
    print(f"Lock SAID: {result.lock_said or '(none)'}")
    print(f"TEL Status: {result.tel_status}")
    print(f"Python Verified: {'Yes' if result.python_verified else 'No'}")
    print(f"Packages Verified: {result.packages_verified}")
    print()

    if result.mismatches:
        print("Mismatches:")
        for m in result.mismatches:
            if m.reason == "missing":
                print(f"  [MISSING] {m.name}: expected {m.expected_version}")
            elif m.reason == "version_mismatch":
                print(f"  [MISMATCH] {m.name}: {m.actual_version} (expected {m.expected_version})")
            elif m.reason == "extra":
                print(f"  [EXTRA] {m.name}: {m.actual_version}")
        print()

    if result.verified:
        print("VERIFIED: Environment matches installation credential")
        return 0
    else:
        print(f"FAILED: {result.error}")
        print("\nRun: governed-stack install <stack-said> --venv --credential")
        return 1


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Governed Stack - KERI-governed dependency management",
        epilog="HYPER-EXPERIMENTAL: API may change without notice.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="governed-stack 0.1.0 (HYPER-EXPERIMENTAL)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init - NEW
    p_init = subparsers.add_parser("init", help="Initialize governance from pyproject.toml")
    p_init.add_argument("--path", "-p", default=".", help="Project path (default: current dir)")
    p_init.add_argument("--controller", "-c", help="Controller AID (default: auto-generated)")
    p_init.set_defaults(func=cmd_init)

    # diff - NEW
    p_diff = subparsers.add_parser("diff", help="Compare with another project")
    p_diff.add_argument("path", help="Path to other project or pyproject.toml")
    p_diff.set_defaults(func=cmd_diff)

    # sync - NEW
    p_sync = subparsers.add_parser("sync", help="Update pyproject.toml with governance metadata")
    p_sync.add_argument("--path", "-p", default=".", help="Project path (default: current dir)")
    p_sync.add_argument("--controller", "-c", help="Controller AID (optional)")
    p_sync.set_defaults(func=cmd_sync)

    # workspace - NEW
    p_workspace = subparsers.add_parser("workspace", help="Govern all projects in a directory")
    p_workspace.add_argument("--path", "-p", default=".", help="Workspace path (default: current dir)")
    p_workspace.add_argument("--resolve", "-r", action="store_true", help="Show resolved constraints")
    p_workspace.add_argument("--sync", "-s", action="store_true", help="Apply resolved constraints to all projects")
    p_workspace.add_argument("--controller", "-c", help="Controller AID for workspace")
    p_workspace.add_argument("--tel", action="store_true", help="Issue TEL-anchored credentials (requires KERI)")
    p_workspace.set_defaults(func=cmd_workspace)

    # define
    p_define = subparsers.add_parser("define", help="Define a governed stack")
    p_define.add_argument("name", help="Stack name")
    p_define.add_argument("--controller", "-c", required=True, help="Controller AID")
    p_define.add_argument(
        "--stack", "-s",
        help=f"Preset stack or JSON file. Presets: {', '.join(PRESET_STACKS.keys())}",
    )
    p_define.add_argument("--rationale", "-r", help="Rationale for these constraints")
    p_define.set_defaults(func=cmd_define)

    # check
    p_check = subparsers.add_parser("check", help="Check compliance")
    p_check.add_argument("said", nargs="?", help="Stack SAID or name (default: current project)")
    p_check.set_defaults(func=cmd_check)

    # install
    p_install = subparsers.add_parser("install", help="Install dependencies")
    p_install.add_argument("said", help="Stack SAID or name")
    p_install.add_argument("--uv", action="store_true", help="Use UV (default)")
    p_install.add_argument("--pip", action="store_true", help="Use pip instead of UV")
    p_install.add_argument("--upgrade", "-U", action="store_true", help="Upgrade packages")
    p_install.add_argument(
        "--venv",
        nargs="?",
        const=True,
        default=None,
        metavar="PATH",
        help="Create venv before install (default: .venv). Uses Python version from stack.",
    )
    p_install.add_argument(
        "--credential-path",
        metavar="PATH",
        help="Path for credential output (default: .governed/installation.json)",
    )
    p_install.add_argument(
        "--issuer",
        metavar="AID",
        help="(DEPRECATED) Issuer AID for credential. Use KERI session for TEL-anchored credentials.",
    )
    p_install.set_defaults(func=cmd_install)

    # generate
    p_gen = subparsers.add_parser("generate", help="Generate pyproject.toml or requirements.txt")
    p_gen.add_argument("said", help="Stack SAID or name")
    p_gen.add_argument("--pyproject", action="store_true", help="Generate pyproject.toml (default)")
    p_gen.add_argument("--requirements", action="store_true", help="Generate requirements.txt")
    p_gen.add_argument("--output", "-o", help="Output file (default: stdout)")
    p_gen.set_defaults(func=cmd_generate)

    # list
    p_list = subparsers.add_parser("list", help="List defined stacks")
    p_list.set_defaults(func=cmd_list)

    # verify - NEW
    p_verify = subparsers.add_parser("verify", help="Verify installed environment matches credential")
    p_verify.add_argument("--credential", "-c", help="Path to installation credential (default: .governed/installation.json)")
    p_verify.add_argument("--venv", "-v", help="Path to venv (default: from credential or .venv)")
    # No --no-strict option. Extra packages are a supply chain attack vector.
    # SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
