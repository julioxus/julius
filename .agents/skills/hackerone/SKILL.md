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
4. Read `.agents/agents/hackerone-intel-fetcher.md` when you need Codex-native delegation for disclosed-report intel.

## Rules

- Parse HackerOne scope and out-of-scope data first.
- Register or query engagement state in Bounty Intel before creating duplicate local state.
- Run the pentest workflow in sub-orchestrator mode after scope parsing.
- For Codex delegation, use the prompts in `.agents/agents/` instead of the Claude agent files directly.
- Use `python -m bounty_intel agent dispatch --name intel ... --json` for disclosed-report lookup roles and `--name orchestrator|executor|validator` for testing roles.
- Preserve reporting gates from `AGENTS.md`, especially `No PoC = No Report`.
