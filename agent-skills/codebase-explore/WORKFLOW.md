# Codebase Explore Workflow

Use this workflow when the user wants to understand the codebase, find streamlining opportunities, explore architecture, or map module dependencies.

## Use Cases

- "Streamline this codebase"
- "How does X work?"
- "Find duplication"
- "Map the architecture"
- "What can we simplify?"

## Approach

1. **Map structure**: Read `src/` layout from CLAUDE.md or `find src -name "*.rs"`. Identify main modules: cli, engine, providers, registry, virtual_adversary, virtual_adversary2, effectiveness, hardening, posture, payload, http, etc.

2. **Trace dependencies**: Follow `mod` declarations and `use` statements. Key entry points: `main.rs` → `cli`, `lib.rs` for traits and types.

3. **Find duplication**:
   - Duplicate enums (e.g. OutputFormat, ProbeChannel)
   - Repeated patterns (consent guard, output formatting)
   - Similar logic in multiple files

4. **Identify complexity hotspots**: Files >1000 lines, deep nesting, many responsibilities in one module.

5. **Check streamlining plan**: If one exists, read `docs/STREAMLINING_PLAN.md` for tracked opportunities and phase status.

## Output

Produce a structured summary with:
- Module map and dependencies
- Duplication findings with file:line references
- Complexity hotspots
- Concrete recommendations (tied to plan phases when applicable)

## Rules

- Use actual code references, not invented ones
- Prefer `docs/STREAMLINING_PLAN.md` as the canonical list of streamlining work
- When proposing new work, consider whether it belongs in the plan
