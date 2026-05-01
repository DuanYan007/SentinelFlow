# Memory Refresh Mechanism

## Purpose
- Keep long-term project memory accurate and compact.
- Prevent stale planning notes from polluting later implementation work.

## Memory Layers

### `stable-context.md`
Store only:
- durable project facts
- confirmed user preferences
- confirmed architecture decisions
- reusable constraints

Do not store:
- temporary guesses
- one-off tool outputs
- unresolved experiments

### `active-context.md`
Store:
- current stage
- immediate next tasks
- unresolved questions
- latest session state

Refresh this file frequently.

### `decision-log.md`
Append or update when:
- the user confirms a design choice
- a baseline changes
- a tool choice is fixed
- an evaluation rule is finalized

## Refresh Triggers
- After a planning session with new confirmed choices
- After architecture changes
- Before starting implementation
- After finishing a milestone
- After any major experiment result that changes direction

## Refresh Procedure
1. Review recent confirmed user instructions.
2. Move durable conclusions into `stable-context.md`.
3. Update `active-context.md` with current stage and next actions.
4. Record changed decisions in `decision-log.md`.
5. Remove stale or superseded items from `active-context.md`.

## Promotion Rules
- Promote to stable only if the item is:
  - confirmed by the user
  - expected to matter across future sessions
  - unlikely to change frequently

## Pruning Rules
- If an active item is completed, remove it from `active-context.md`.
- If an active item becomes durable, move it to `stable-context.md`.
- If an old decision is overturned, update `decision-log.md` and revise `stable-context.md`.

## Implementation-Start Checkpoint
Before writing code:
- confirm with the user
- review `active-context.md`
- verify whether any open choice blocks implementation

## Suggested Update Discipline
- Lightweight refresh:
  - after each planning session
- Full refresh:
  - before implementation
  - after a completed milestone
