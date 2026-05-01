---
name: project-memory
description: Use when working on this ransomware detection project across multiple sessions and you need to preserve, refresh, or consult project memory stored in workspace files before planning or implementation.
---

# Project Memory

Use this skill for continuity in this repository.

## Files
- `project-memory/stable-context.md`
- `project-memory/active-context.md`
- `project-memory/decision-log.md`
- `project-memory/memory-refresh-mechanism.md`

## Workflow
- Read `stable-context.md` first for durable project facts.
- Read `active-context.md` second for current priorities and unresolved items.
- Read `decision-log.md` only when you need the reasoning trail of confirmed choices.
- Update project memory after meaningful planning or architecture changes.

## Update Rules
- Put durable confirmed facts into stable memory.
- Put temporary status and next steps into active memory.
- Keep entries short and concrete.
- Remove stale active items when they are completed or replaced.
- Before any implementation work, check whether memory says the user wants confirmation first.

## Refresh Trigger
- Trigger a memory refresh whenever:
  - the user confirms new experiment choices
  - the architecture changes
  - implementation is about to start
  - a milestone changes the plan
