---
name: intigriti
description: Julius Intigriti bug bounty workflow for Codex. Use when the user wants to work an Intigriti program, parse Intigriti scope, or refers to the Claude /intigriti workflow.
user-invocable: true
---

# Intigriti

Use the Julius Intigriti workflow from Codex.

## Load Order

1. Read `.claude/skills/intigriti/SKILL.md`.
2. Read `.claude/skills/pentest/SKILL.md` because `/intigriti` delegates testing to `/pentest`.
3. Read `.claude/agents/CLAUDE.md` before active testing.

## Rules

- Preserve Intigriti-specific testing requirements such as mandatory headers or user agents.
- Parse scope and restrictions first, then hand off to the pentest workflow in sub-orchestrator mode.
- Use Bounty Intel as the source of truth for engagement and findings state.
- Preserve the repository reporting and evidence standards from `AGENTS.md`.
