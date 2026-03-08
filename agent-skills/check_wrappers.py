#!/usr/bin/env python3

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent

SKILLS = {
    "waf-assess": {
        "workflow": "agent-skills/waf-assess/WORKFLOW.md",
        "description": (
            "Use when the user wants an end-to-end WAF assessment workflow "
            "instead of a single CLI command."
        ),
    },
    "cli-doctor": {
        "workflow": "agent-skills/cli-doctor/WORKFLOW.md",
        "description": (
            "Use when scans fail early, the environment looks unhealthy, "
            "or the user wants shell completions."
        ),
    },
    "security-audit": {
        "workflow": "agent-skills/security-audit/WORKFLOW.md",
        "description": (
            "Use when the user wants a structured security review, hardening "
            "pass, or pre-release audit."
        ),
    },
    "validate-build": {
        "workflow": "agent-skills/validate-build/WORKFLOW.md",
        "description": (
            "Use when the user wants final formatting, lint, test, and build "
            "validation before merge or push."
        ),
    },
}


def render_claude_wrapper(skill_name: str, description: str, workflow: str) -> str:
    return (
        f"---\n"
        f"name: {skill_name}\n"
        f"description: {description}\n"
        f"---\n\n"
        f"# Claude wrapper for the shared {skill_name} workflow.\n\n"
        f"Source of truth: `{workflow}`\n\n"
        f"Read the shared workflow before taking action.\n"
        f"If this wrapper and the shared workflow disagree, follow the shared "
        f"workflow and update the wrapper in the same change.\n"
    )


def render_codex_wrapper(skill_name: str, description: str, workflow: str) -> str:
    return (
        f"---\n"
        f"name: {skill_name}\n"
        f"description: {description}\n"
        f"---\n\n"
        f"This is a thin Codex wrapper.\n\n"
        f"Source of truth: `{workflow}`\n\n"
        f"Read the shared workflow before taking action.\n"
        f"If this wrapper and the shared workflow disagree, follow the shared "
        f"workflow and update the wrapper in the same change.\n"
    )


def expected_wrappers(skill_name: str, description: str, workflow: str) -> dict[str, str]:
    return {
        f".claude/skills/{skill_name}.md": render_claude_wrapper(
            skill_name, description, workflow
        ),
        f".codex/skills/{skill_name}/SKILL.md": render_codex_wrapper(
            skill_name, description, workflow
        ),
    }


def main() -> int:
    failures: list[str] = []

    for skill_name, config in SKILLS.items():
        workflow = config["workflow"]
        description = config["description"]
        workflow_path = REPO_ROOT / workflow
        if not workflow_path.exists():
            failures.append(f"{skill_name}: missing workflow {workflow}")
            continue

        for wrapper, expected in expected_wrappers(
            skill_name, description, workflow
        ).items():
            wrapper_path = REPO_ROOT / wrapper
            if not wrapper_path.exists():
                failures.append(f"{skill_name}: missing wrapper {wrapper}")
                continue

            actual = wrapper_path.read_text(encoding="utf-8")
            if actual != expected:
                failures.append(
                    f"{skill_name}: wrapper {wrapper} does not match the expected thin wrapper format"
                )

    if failures:
        print("Wrapper validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("All shared skill wrappers match the expected thin wrapper format.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
