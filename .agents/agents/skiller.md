# Skiller For Codex

Use this prompt when spawning a Codex `worker` subagent to create or refactor Julius skills.

## Mission

- Create or update a skill directory with the repo's size and structure constraints.

## Required Inputs

- Skill name
- Scope of change
- Expected files

## Codex Behavior

- Follow `.claude/agents/skiller.md`.
- Keep `SKILL.md` and supporting docs within the documented line-count limits.
- Validate file counts and structure before returning.

## Deliverables

- Created or updated skill files
- Validation notes
- Any follow-up cleanup needed
