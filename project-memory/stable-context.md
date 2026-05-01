# Stable Context

## Project
- Topic: ransomware detection research
- Goal: build and evaluate a multi-stage ransomware detection framework
- Core idea: `hash intelligence -> Agent decision -> static or dynamic analysis -> final classification`

## User Preferences
- Use question-and-answer flow with options when planning.
- Keep explanations short unless deeper analysis is requested.
- Confirm with the user before writing implementation code.
- Store long-term memory inside project files.
- Keep a project-root rules file so future sessions have an explicit startup convention.
- Use a project-local virtual environment to avoid polluting the experiment environment.
- Prefer `uv` for environment and package management when possible.

## Durable Research Decisions
- Main experiment focus:
  - Detection effectiveness
  - Agent value in automated intelligent decision-making
- Primary sample source:
  - Self-collected real samples
  - Current scale: `300+` ransomware samples
- First implementation target:
  - Minimal closed loop
  - `hash -> Agent -> static/dynamic -> final classification`
- Threat intelligence priority:
  - Use `VirusTotal` first
  - If VT misses or is insufficient, Agent chooses next path
  - The user currently prefers storing VT credentials in a local config file rather than environment variables
- Agent design:
  - `LLM + rules + scoring + skill/tool calling`
  - LLM handles decision, orchestration, and explanation
- Static analysis strategy:
  - Do not execute PE
  - Prefer existing tools
  - First version focuses on key static features
  - Static scoring uses mixed features:
    - PE structure
    - suspicious imports/APIs
    - strings/config traces
- Dynamic analysis strategy:
  - Run in sandbox/VM
  - Prefer existing sandbox/behavior tools
  - First version focuses on key dynamic behaviors
  - Dynamic signals include:
    - file behaviors
    - encryption-related behaviors
    - destructive/system-impact behaviors
- Decision flow:
  - If static result is uncertain, add one dynamic analysis pass
  - Phase 1 priority is end-to-end workflow validation, so avoid early termination shortcuts
- Final output:
  - Three classes: `malicious / suspicious / benign`
- Result format:
  - `JSON`
  - Include base fields, Agent path/skills/reasons, VT/static/dynamic evidence
  - First version uses the complete record style:
    - sample metadata
    - Agent path
    - step-by-step reasons
    - static/dynamic scores
    - matched features
    - invoked skills/tools
- Experiment environment:
  - Local sandbox or VM
  - Current host environment: Ubuntu 24.04
- Execution progression:
  - `single sample -> small batch -> full batch`
  - Single-sample first target:
    - a sample with clear malicious VT verdict
  - Small-batch next target:
    - prioritize VT high-confidence malicious samples
    - add a small benign set for initial false-positive observation
- Baselines:
  - `hash -> static -> dynamic -> verdict`
  - `hash -> static -> verdict`
  - `hash -> dynamic -> verdict`

## Long-Term Constraints
- Long-running project; preserve decisions and open questions across sessions.
- Stable memory should only store durable facts, confirmed decisions, and reusable rules.
