---
name: julius
description: Codex compatibility bridge for the Julius security testing toolkit. Use when the user wants to run Julius workflows from Codex, or mentions Claude slash commands such as /pentest, /hackerone, /intigriti, or /defectdojo.
user-invocable: true
---

# Julius For Codex

This repository was originally designed around Claude Code slash commands and agent prompts in `.claude/`.

When the user asks to use Julius from Codex:

1. Treat Claude slash commands as workflow intents, not literal commands.
2. Read the matching source workflow in `.claude/skills/<name>/SKILL.md`.
3. Load shared executor rules from `.claude/agents/CLAUDE.md` when the workflow deploys testing agents or touches findings or evidence.
4. Follow the repository root `AGENTS.md` as the passive security knowledge base.

## Workflow Mapping

- `/pentest` -> `.claude/skills/pentest/SKILL.md`
- `/hackerone` -> `.claude/skills/hackerone/SKILL.md` then `.claude/skills/pentest/SKILL.md`
- `/intigriti` -> `.claude/skills/intigriti/SKILL.md` then `.claude/skills/pentest/SKILL.md`
- `/defectdojo` -> `.claude/skills/defectdojo/SKILL.md` then `.claude/skills/pentest/SKILL.md`

## Operating Rules

- Prefer retrieval-led reasoning for security tasks.
- Use Bounty Intel as the source of truth for programs, findings, reports, submissions, and recon data.
- If `bounty_*` MCP tools are unavailable in the current Codex session, fall back to the local Python implementation in `bounty_intel/`.
- Preserve the same safety model documented for Claude:
  - scope validation via `tools/scope_checker.py`
  - outbound request checks via `tools/safety_rails.py`
  - artifacts under `outputs/<engagement>/`
- Never invent findings, endpoints, or evidence. The repo policy is `No PoC = No Report`.
