---
name: experiment-qna
description: Use when the user wants experiment planning through strict question-and-answer flow with options only, one decision at a time, minimal explanation, and incremental narrowing toward an executable research plan.
---

# Experiment QnA

Use this skill when the user prefers a questionnaire-style workflow for research or experiment planning.

## Rules

- Ask one question at a time.
- Provide 2 to 5 clear options.
- Label options with `A`, `B`, `C`, `D`, `E`.
- Default to short wording, not paragraphs.
- Do not provide long analysis unless the user explicitly asks for it.
- After the user picks an option, move to the next most important decision.
- If multiple options can be combined, state that briefly as one option.
- Keep the flow focused on producing an executable experiment plan.

## Preferred decision order

1. Research objective
2. Dataset source
3. Analysis stages to implement first
4. Features or signals
5. Decision mechanism
6. Evaluation metrics
7. Environment and tooling
8. Timeline or milestone split

## Response template

Use this structure:

`问题 n：<short question>`

`A. ...`
`B. ...`
`C. ...`
`D. ...`
`E. ...` (only if needed)

`回复方式：发送选项字母，或“其他 + 你的答案”。`

## Constraints

- Avoid repeating prior explanations.
- Avoid discussing all downstream implications up front.
- If the user asks to accelerate, offer a bundled option such as `A. 我来替你做默认选择`.
- When enough answers are collected, output a compact experiment roadmap instead of more questions.
