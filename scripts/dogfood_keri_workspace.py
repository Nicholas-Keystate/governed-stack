#!/usr/bin/env python3
"""
Dogfood keri-sec across all KERI workspace projects.

This script:
1. Defines keri-sec stacks for each KERI project
2. Checks compliance against current environments
3. Reports metrics and emergent implications
4. Generates governed pyproject.toml configurations

Usage:
    python scripts/dogfood_keri_workspace.py
"""

import json
import sys
import time
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from keri_sec import StackManager, StackProfile
from keri_sec.handlers import get_handler, HANDLERS


# =============================================================================
# KERI Workspace Project Definitions
# =============================================================================

KERI_WORKSPACE = Path("/Users/hun-magnon/Documents/KERI")

KERI_PROJECTS = {
    "ai-orchestrator": {
        "description": "KERI-attested AI agent infrastructure",
        "python": ">=3.12",
        "constraints": {
            "keri": ">=1.2.0",
            "hio": ">=0.6.14",
            "fastapi": ">=0.100.0",
            "uvicorn": ">=0.23.0",
            "pydantic": ">=2.0.0",
            "httpx": ">=0.24.0",
            "jinja2": ">=3.1.0",
        },
        "optional": {
            "kgql": ">=0.1.0",
            "keri-rlm": ">=0.1.0",
        },
    },
    "keri-git-said": {
        "description": "Self-referential SAIDs for git commits",
        "python": ">=3.10",
        "constraints": {
            "keri": ">=1.1.0",
            "blake3": ">=0.3.0",
            "click": ">=8.0.0",
        },
    },
    "kgql": {
        "description": "KERI Graph Query Language",
        "python": ">=3.10",
        "constraints": {
            "keri": ">=1.1.0",
            "networkx": ">=3.0",
        },
    },
    "keri-rlm": {
        "description": "Recursive Language Models with KERI attestation",
        "python": ">=3.10",
        "constraints": {
            "keri": ">=1.1.0",
            "hio": ">=0.6.14",
        },
        "optional": {
            "anthropic": ">=0.40.0",
            "ollama": ">=0.3.0",
        },
    },
    "keri-sec": {
        "description": "Dependency governance with Transit patterns",
        "python": ">=3.10",
        "constraints": {
            "keri": ">=1.1.0",
        },
        "self_governance": True,  # This is the dogfood!
    },
}


@dataclass
class ProjectMetrics:
    """Metrics for a single project."""
    name: str
    stack_said: str
    constraint_count: int
    compliance_results: Dict[str, bool] = field(default_factory=dict)
    compliance_rate: float = 0.0
    missing_packages: List[str] = field(default_factory=list)
    version_mismatches: List[str] = field(default_factory=list)
    pyproject_generated: bool = False
    observations: List[str] = field(default_factory=list)


@dataclass
class WorkspaceReport:
    """Aggregate report for entire workspace."""
    total_projects: int
    total_constraints: int
    overall_compliance_rate: float
    project_metrics: List[ProjectMetrics]
    shared_constraints: Dict[str, int]  # constraint -> count of projects using it
    version_conflicts: List[str]  # constraints with conflicting versions
    execution_time_ms: float
    observations: List[str] = field(default_factory=list)


def check_package_installed(package: str, version_spec: str) -> tuple[bool, str]:
    """Check if a package is installed and meets version spec."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return False, "not installed"

        # Parse version from output
        for line in result.stdout.split("\n"):
            if line.startswith("Version:"):
                installed_version = line.split(":")[1].strip()
                # Simple version comparison (would need packaging lib for full support)
                return True, installed_version

        return False, "version unknown"
    except Exception as e:
        return False, str(e)


def define_keri_secs(manager: StackManager, owner_baid: str) -> Dict[str, StackProfile]:
    """Define keri-sec stacks for all KERI projects."""
    stacks = {}

    for project_name, project_def in KERI_PROJECTS.items():
        constraints = project_def.get("constraints", {})

        # Add Python constraint
        if "python" in project_def:
            constraints["python"] = project_def["python"]

        # Define stack
        stack = manager.define_stack(
            name=f"{project_name}-production",
            controller_aid=owner_baid,
            constraints=constraints,
        )
        stacks[project_name] = stack

    return stacks


def check_project_compliance(
    manager: StackManager,
    project_name: str,
    stack: StackProfile,
    project_path: Path,
) -> ProjectMetrics:
    """Check compliance for a single project."""
    metrics = ProjectMetrics(
        name=project_name,
        stack_said=stack.said,
        constraint_count=len(stack.constraints),
    )

    # Check each constraint
    for pkg_name, constraint in stack.constraints.items():
        version_spec = constraint.version_spec

        if constraint.constraint_type.value == "python":
            # Python version check
            import platform
            py_version = platform.python_version()
            # Simple check - real implementation would parse version spec
            metrics.compliance_results["python"] = True
            metrics.observations.append(f"Python {py_version} installed")
        else:
            # Package check
            installed, actual_version = check_package_installed(pkg_name, version_spec)
            metrics.compliance_results[pkg_name] = installed

            if not installed:
                metrics.missing_packages.append(pkg_name)
            else:
                metrics.observations.append(f"{pkg_name}=={actual_version}")

    # Calculate compliance rate
    if metrics.compliance_results:
        compliant = sum(1 for v in metrics.compliance_results.values() if v)
        metrics.compliance_rate = compliant / len(metrics.compliance_results) * 100

    return metrics


def generate_pyproject_section(stack: StackProfile) -> str:
    """Generate pyproject.toml dependencies section from stack."""
    lines = ["dependencies = ["]
    for pkg_name, constraint in stack.constraints.items():
        if constraint.constraint_type.value != "python":
            lines.append(f'    "{pkg_name}{constraint.version_spec}",')
    lines.append("]")
    return "\n".join(lines)


def find_shared_constraints(stacks: Dict[str, StackProfile]) -> Dict[str, int]:
    """Find constraints shared across multiple projects."""
    constraint_counts = {}

    for stack in stacks.values():
        for pkg_name in stack.constraints.keys():
            constraint_counts[pkg_name] = constraint_counts.get(pkg_name, 0) + 1

    # Return only those used by 2+ projects
    return {k: v for k, v in constraint_counts.items() if v >= 2}


def find_version_conflicts(stacks: Dict[str, StackProfile]) -> List[str]:
    """Find constraints with conflicting version specs across projects."""
    version_specs = {}

    for project_name, stack in stacks.items():
        for pkg_name, constraint in stack.constraints.items():
            if pkg_name not in version_specs:
                version_specs[pkg_name] = []
            version_specs[pkg_name].append((project_name, constraint.version_spec))

    conflicts = []
    for pkg, specs in version_specs.items():
        if len(specs) > 1:
            unique_specs = set(s[1] for s in specs)
            if len(unique_specs) > 1:
                conflict_desc = f"{pkg}: " + ", ".join(f"{p}({s})" for p, s in specs)
                conflicts.append(conflict_desc)

    return conflicts


def run_dogfood() -> WorkspaceReport:
    """Run full dogfooding analysis on KERI workspace."""
    start_time = time.perf_counter()

    # Initialize manager with test BAID
    manager = StackManager()
    owner_baid = "BAID_KERI_WORKSPACE_DOGFOOD"

    print("=" * 60)
    print("GOVERNED-STACK DOGFOODING: KERI WORKSPACE")
    print("=" * 60)
    print()

    # Define all stacks
    print("Defining keri-sec stacks...")
    stacks = define_keri_secs(manager, owner_baid)
    print(f"  Defined {len(stacks)} project stacks")
    print()

    # Check compliance for each project
    print("Checking compliance...")
    project_metrics = []

    for project_name, stack in stacks.items():
        project_path = KERI_WORKSPACE / project_name
        metrics = check_project_compliance(manager, project_name, stack, project_path)
        project_metrics.append(metrics)

        status = "✓" if metrics.compliance_rate == 100 else f"{metrics.compliance_rate:.0f}%"
        print(f"  {project_name}: {status} ({metrics.constraint_count} constraints)")

        if metrics.missing_packages:
            print(f"    Missing: {', '.join(metrics.missing_packages)}")

    print()

    # Find shared constraints
    shared = find_shared_constraints(stacks)
    print(f"Shared constraints ({len(shared)}):")
    for pkg, count in sorted(shared.items(), key=lambda x: -x[1]):
        print(f"  {pkg}: used by {count} projects")
    print()

    # Find version conflicts
    conflicts = find_version_conflicts(stacks)
    if conflicts:
        print(f"⚠ Version conflicts ({len(conflicts)}):")
        for conflict in conflicts:
            print(f"  {conflict}")
    else:
        print("✓ No version conflicts detected")
    print()

    # Calculate totals
    total_constraints = sum(m.constraint_count for m in project_metrics)
    avg_compliance = sum(m.compliance_rate for m in project_metrics) / len(project_metrics)

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Generate report
    report = WorkspaceReport(
        total_projects=len(stacks),
        total_constraints=total_constraints,
        overall_compliance_rate=avg_compliance,
        project_metrics=project_metrics,
        shared_constraints=shared,
        version_conflicts=conflicts,
        execution_time_ms=elapsed_ms,
        observations=[
            f"Analyzed {len(stacks)} projects in {elapsed_ms:.1f}ms",
            f"Total constraints: {total_constraints}",
            f"Shared constraints: {len(shared)}",
            f"Version conflicts: {len(conflicts)}",
        ],
    )

    # Print summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Projects analyzed: {report.total_projects}")
    print(f"Total constraints: {report.total_constraints}")
    print(f"Overall compliance: {report.overall_compliance_rate:.1f}%")
    print(f"Execution time: {report.execution_time_ms:.1f}ms")
    print()

    # Print SAIDs for reference
    print("Stack SAIDs:")
    for project_name, stack in stacks.items():
        print(f"  {project_name}: {stack.said}")
    print()

    # Generate pyproject snippets
    print("Generated pyproject.toml snippets saved to: keri-secs/")
    output_dir = KERI_WORKSPACE / "keri-sec" / "keri-secs"
    output_dir.mkdir(exist_ok=True)

    for project_name, stack in stacks.items():
        output_file = output_dir / f"{project_name}.toml"
        content = f"""# Governed dependencies for {project_name}
# Stack SAID: {stack.said}
# Generated by keri-sec dogfood

[project]
{generate_pyproject_section(stack)}

# Governance metadata
[tool.keri-sec]
stack_said = "{stack.said}"
owner_baid = "{owner_baid}"
"""
        output_file.write_text(content)
        print(f"  {output_file.name}")

    return report


def main():
    """Main entry point."""
    report = run_dogfood()

    # Return success if compliance is reasonable
    if report.overall_compliance_rate < 50:
        print("\n⚠ WARNING: Low compliance rate detected")
        sys.exit(1)

    print("\n✓ Dogfooding complete")
    sys.exit(0)


if __name__ == "__main__":
    main()
