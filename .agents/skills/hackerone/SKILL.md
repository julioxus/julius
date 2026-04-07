---
name: hackerone
description: Julius HackerOne bug bounty workflow for Codex. Use when the user wants to work a HackerOne program, parse HackerOne scope, or refers to the Claude /hackerone workflow.
user-invocable: true
---

# HackerOne

Use the Julius HackerOne workflow from Codex.

## Load Order

1. Read `.claude/skills/hackerone/SKILL.md`.
2. Read `.claude/skills/pentest/SKILL.md` because `/hackerone` delegates testing to `/pentest`.
3. Read `.claude/agents/CLAUDE.md` before active testing.

## Rules

- Parse HackerOne scope and out-of-scope data first.
- Register or query engagement state in Bounty Intel before creating duplicate local state.
- Run the pentest workflow in sub-orchestrator mode after scope parsing.
- Preserve reporting gates from `AGENTS.md`, especially `No PoC = No Report`.
