# Agent Guidance

This repository is meant to be comfortable for both Codex and Claude.

## Source Of Truth

Shared agent workflows live under `agent-skills/`. These files contain the real workflow logic:

- `agent-skills/waf-assess/WORKFLOW.md`
- `agent-skills/cli-doctor/WORKFLOW.md`
- `agent-skills/security-audit/WORKFLOW.md`
- `agent-skills/validate-build/WORKFLOW.md`
- `agent-skills/codebase-explore/WORKFLOW.md`
- `agent-skills/provider-dev/WORKFLOW.md`

Agent-specific wrappers must stay thin:

- Claude wrappers live in `.claude/skills/*.md`
- Codex wrappers live in `.codex/skills/*/SKILL.md`

If a wrapper and a shared workflow disagree, follow the shared workflow and fix the wrapper in the same change.

## Mapping

- Full scan pipeline, detection, smoke, effectiveness, enforcement, behavioral review, posture reporting, and HTML report rendering:
  `agent-skills/waf-assess/WORKFLOW.md`
- CLI health checks and shell completion setup:
  `agent-skills/cli-doctor/WORKFLOW.md`
- Security review or audit work:
  `agent-skills/security-audit/WORKFLOW.md`
- Build, lint, test, and release validation:
  `agent-skills/validate-build/WORKFLOW.md`
- Codebase exploration, architecture review, streamlining opportunities:
  `agent-skills/codebase-explore/WORKFLOW.md`
- Adding a new WAF/CDN provider:
  `agent-skills/provider-dev/WORKFLOW.md`

## When to Use Which Skill

| User says… | Skill |
|------------|-------|
| "Assess this WAF" / "Full scan" / "Run detection" | waf-assess |
| "Scans failing" / "Environment unhealthy" / "Shell completions" | cli-doctor |
| "Security audit" / "Pre-release review" | security-audit |
| "Validate before merge" / "Run tests" | validate-build |
| "Streamline" / "Understand codebase" / "Find duplication" | codebase-explore |
| "Add new provider" / "Implement detection for X" | provider-dev |

## Mental Model

This project is AI-native agentic tooling. The skills are the primary interface — not the CLI. The CLI exists to serve the skills, not the other way around. When a user asks for a WAF assessment, an agent reads `agent-skills/waf-assess/WORKFLOW.md` and executes the steps; the user never needs to know the flag syntax.

Treat `agent-skills/*/WORKFLOW.md` files as first-class artifacts. They are as important as the source code. When the CLI surface changes — new subcommand, renamed flag, changed output format — update the relevant WORKFLOW.md in the same commit.

## Working Rules

- Prefer targeted tests while iterating. Run the full validation workflow before finalizing broad changes.
- Keep wrapper files short and agent-friendly. Put the actual process in the shared workflow.
- When editing any shared workflow or wrapper, run `python3 agent-skills/check_wrappers.py`.
- When adding probes to `dae.rs` or pairs to `waffled_techniques.rs`, check whether WORKFLOW.md remediation guidance needs updating to reflect new detection categories.
