---
name: cli-doctor
description: Run environment health checks and generate shell completions for waf-detect
user_invocable: true
---

# CLI Doctor Skill

Use this skill to verify the local `waf-detect` runtime environment and set up shell completions.

## When To Use

- Before running scans or assessments to catch environment issues early.
- When command execution is flaky and you need a health report.
- When users want `bash`, `zsh`, or `fish` tab completion.

## Quick Commands

```bash
waf-detect doctor
waf-detect doctor --json
waf-detect doctor --strict
waf-detect completions bash
waf-detect completions zsh
waf-detect completions fish
waf-detect completions zsh -o ~/.zsh/completions/_waf-detect
```

## Decision Logic

- `FAIL`: block the requested workflow and remediate first.
- `WARN`: advisory by default; continue with notes unless strict behavior is requested.
- `PASS`: proceed without gating.
- If strict gating is requested, use `waf-detect doctor --strict` and treat warnings as failures.

## Completion Install Snippets

### zsh

```bash
mkdir -p ~/.zsh/completions
waf-detect completions zsh -o ~/.zsh/completions/_waf-detect
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit
```

### bash

```bash
mkdir -p ~/.local/share/bash-completion/completions
waf-detect completions bash -o ~/.local/share/bash-completion/completions/waf-detect
source ~/.local/share/bash-completion/completions/waf-detect
```

### fish

```bash
mkdir -p ~/.config/fish/completions
waf-detect completions fish -o ~/.config/fish/completions/waf-detect.fish
source ~/.config/fish/completions/waf-detect.fish
```

## Troubleshooting Notes

- Home directory is not writable: write completion output to a writable directory and load it manually from shell config.
- `waf-detect` not found in `PATH`: run with absolute binary path (for example `./target/debug/waf-detect`) or update `PATH`.
- API token warning in doctor output: report which integration is affected; continue for non-dependent commands, or stop if the requested flow requires that token.
