# CLI Doctor Workflow

Use this workflow to validate the local `waf-detect` environment and help users install shell completions.

## Use Cases

- The CLI is failing before scans start
- The user wants a health report
- The user wants `bash`, `zsh`, or `fish` completion support

## Commands

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

- `FAIL`: stop and remediate before continuing
- `WARN`: continue with notes unless strict behavior is required
- `PASS`: proceed

If strict gating is needed, use `waf-detect doctor --strict`.

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

- If the home directory is not writable, emit completion files to a writable path and tell the user how to source them.
- If `waf-detect` is not in `PATH`, use the built binary path directly.
- If doctor reports missing API tokens, say which workflow is affected and whether that warning blocks the requested task.
