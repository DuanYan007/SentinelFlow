# Agent Rules

This file defines default working rules for this repository.

## Default Startup Order
When starting a new task in this project:
1. Read `project-memory/stable-context.md`
2. Read `project-memory/active-context.md`
3. Read `skills/project-memory/SKILL.md` if memory needs refresh or interpretation
4. If the task is planning-oriented, follow `skills/experiment-qna/SKILL.md`

## Planning Mode
- Prefer question-and-answer flow with options.
- Ask one question at a time.
- Keep explanations short unless the user asks for detail.
- Record durable confirmed choices into project memory.

## Implementation Guardrail
- Before writing implementation code, confirm with the user first.
- Before implementation, review open items in `project-memory/active-context.md`.

## Memory Discipline
- Stable facts go to `project-memory/stable-context.md`
- Current stage and pending items go to `project-memory/active-context.md`
- Confirmed decisions go to `project-memory/decision-log.md`
- Refresh memory according to `project-memory/memory-refresh-mechanism.md`

## Scope
- These rules are project-local and intended for long-running continuity.
