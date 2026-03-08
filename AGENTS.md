# Agent Guidance

This repository is set up to be worked on by both Codex and Claude.

## Shared Workflow Sources

The project-specific workflow docs live in `.claude/skills/`. Treat these files as the source of truth for agent workflows:

- `.claude/skills/waf-assess.md`
- `.claude/skills/cli-doctor.md`
- `.claude/skills/security-audit.md`
- `.claude/skills/validate-build.md`

When a task clearly matches one of those workflows, read the corresponding file and follow it unless the user asks for something narrower.

## Mapping

- Full scan pipeline, consent flow, detection, smoke, effectiveness, enforcement, behavioral review: `.claude/skills/waf-assess.md`
- CLI environment checks and shell completion setup: `.claude/skills/cli-doctor.md`
- Security review or audit work: `.claude/skills/security-audit.md`
- Build, lint, test, and release validation: `.claude/skills/validate-build.md`

## Working Rules

- Keep agent-specific wrappers thin. Update the workflow file in `.claude/skills/` first when behavior changes.
- Preserve consent and authorization checks for effectiveness, enforcement, and behavioral testing.
- Prefer targeted tests while iterating. Run the full validation workflow before finalizing broad changes.
- If a workflow doc becomes stale relative to the CLI or code, fix the doc in the same change.
