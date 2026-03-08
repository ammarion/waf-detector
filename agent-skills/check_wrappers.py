#!/usr/bin/env python3

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent

SKILLS = {
    "waf-assess": {
        "workflow": "agent-skills/waf-assess/WORKFLOW.md",
        "wrappers": [
            ".claude/skills/waf-assess.md",
            ".codex/skills/waf-assess/SKILL.md",
        ],
    },
    "cli-doctor": {
        "workflow": "agent-skills/cli-doctor/WORKFLOW.md",
        "wrappers": [
            ".claude/skills/cli-doctor.md",
            ".codex/skills/cli-doctor/SKILL.md",
        ],
    },
    "security-audit": {
        "workflow": "agent-skills/security-audit/WORKFLOW.md",
        "wrappers": [
            ".claude/skills/security-audit.md",
            ".codex/skills/security-audit/SKILL.md",
        ],
    },
    "validate-build": {
        "workflow": "agent-skills/validate-build/WORKFLOW.md",
        "wrappers": [
            ".claude/skills/validate-build.md",
            ".codex/skills/validate-build/SKILL.md",
        ],
    },
}


def main() -> int:
    failures: list[str] = []

    for skill_name, config in SKILLS.items():
        workflow = config["workflow"]
        workflow_path = REPO_ROOT / workflow
        if not workflow_path.exists():
            failures.append(f"{skill_name}: missing workflow {workflow}")
            continue

        marker = f"Source of truth: `{workflow}`"

        for wrapper in config["wrappers"]:
            wrapper_path = REPO_ROOT / wrapper
            if not wrapper_path.exists():
                failures.append(f"{skill_name}: missing wrapper {wrapper}")
                continue

            contents = wrapper_path.read_text(encoding="utf-8")
            if marker not in contents:
                failures.append(
                    f"{skill_name}: wrapper {wrapper} does not point at {workflow}"
                )

    if failures:
        print("Wrapper validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("All shared skill wrappers point to the expected workflows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
