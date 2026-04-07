---
name: defectdojo
description: Julius DefectDojo assessment workflow for Codex. Use when the user wants to run the DefectDojo orchestration, review an engagement, or refers to the Claude /defectdojo workflow.
user-invocable: true
---

# DefectDojo

Use the Julius DefectDojo workflow from Codex.

## Load Order

1. Read `.claude/skills/defectdojo/SKILL.md`.
2. Read `.claude/skills/pentest/SKILL.md` because `/defectdojo` delegates testing to `/pentest`.
3. Read `.claude/agents/CLAUDE.md` before active testing.
4. Read `.agents/agents/README.md` before spawning Codex subagents for testing or reporting work.

## Rules

- Determine SAST and DAST expectations from the DefectDojo engagement metadata.
- Keep local report artifacts when the DefectDojo workflow requires them before upload.
- Do not upload to the DefectDojo API without explicit user approval.
- For Codex delegation, use the prompts in `.agents/agents/` instead of the Claude agent files directly.
- Standard dispatch path: `python -m bounty_intel agent dispatch --name orchestrator|executor|validator ... --json`, then use the rendered payload in `spawn_agent`.
- Preserve validation and evidence requirements from `AGENTS.md`.
