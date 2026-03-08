# Agent Guidance

This repository is meant to be comfortable for both Codex and Claude.

## Source Of Truth

Shared agent workflows live under `agent-skills/`. These files contain the real workflow logic:

- `agent-skills/waf-assess/WORKFLOW.md`
- `agent-skills/cli-doctor/WORKFLOW.md`
- `agent-skills/security-audit/WORKFLOW.md`
- `agent-skills/validate-build/WORKFLOW.md`

Agent-specific wrappers must stay thin:

- Claude wrappers live in `.claude/skills/*.md`
- Codex wrappers live in `.codex/skills/*/SKILL.md`

If a wrapper and a shared workflow disagree, follow the shared workflow and fix the wrapper in the same change.

## Mapping

- Full scan pipeline, consent flow, detection, smoke, effectiveness, enforcement, behavioral review, and posture reporting:
  `agent-skills/waf-assess/WORKFLOW.md`
- CLI health checks and shell completion setup:
  `agent-skills/cli-doctor/WORKFLOW.md`
- Security review or audit work:
  `agent-skills/security-audit/WORKFLOW.md`
- Build, lint, test, and release validation:
  `agent-skills/validate-build/WORKFLOW.md`

## Mental Model

This project is AI-native agentic tooling. The skills are the primary interface — not the CLI. The CLI exists to serve the skills, not the other way around. When a user asks for a WAF assessment, an agent reads `agent-skills/waf-assess/WORKFLOW.md` and executes the steps; the user never needs to know the flag syntax.

Treat `agent-skills/*/WORKFLOW.md` files as first-class artifacts. They are as important as the source code. When the CLI surface changes — new subcommand, renamed flag, new consent gate, changed output format — update the relevant WORKFLOW.md in the same commit.

## Working Rules

- Preserve consent and authorization checks for effectiveness, enforcement, and behavioral testing.
- Prefer targeted tests while iterating. Run the full validation workflow before finalizing broad changes.
- Keep wrapper files short and agent-friendly. Put the actual process in the shared workflow.
- When editing any shared workflow or wrapper, run `python3 agent-skills/check_wrappers.py`.
- When adding probes to `dae.rs` or pairs to `waffled_techniques.rs`, check whether WORKFLOW.md remediation guidance needs updating to reflect new detection categories.
