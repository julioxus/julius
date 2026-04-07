# Julius Codex Agents

This directory ports the Julius agent layer to Codex-native subagents without removing the existing Claude agents in `.claude/agents/`.

## Purpose

- Keep `.claude/agents/` as the canonical Claude runtime prompts.
- Provide Codex-facing agent prompts that are designed for `spawn_agent`.
- Make delegation explicit: each Codex skill can pick a prompt here, then spawn a Codex `default`, `worker`, or `explorer` subagent with the right brief.

## Agent Registry

| Codex Agent Prompt | Source Role | Recommended Codex Agent Type | Typical Use |
|---|---|---|---|
| `pentester-orchestrator.md` | `Pentester Orchestrator` | `default` | Plan, batch, coordinate, aggregate |
| `pentester-executor.md` | `Pentester Executor` | `worker` | Run bounded recon or exploit missions |
| `pentester-validator.md` | `Pentester Validator` | `worker` | Validate one finding against evidence |
| `dom-xss-scanner.md` | `dom-xss-scanner` | `worker` | JS-heavy DOM XSS verification |
| `script-generator.md` | `script-generator` | `worker` | Generate non-trivial scripts |
| `patt-fetcher.md` | `patt-fetcher` | `explorer` | Fetch payload intelligence or curated payloads |
| `hackerone-intel-fetcher.md` | `HackerOne Intel Fetcher` | `explorer` | Disclosed-report intel and prioritization |
| `skiller.md` | `skiller` | `worker` | Create or refactor Julius skills |
| `hackthebox.md` | `hackthebox` | `default` | End-to-end HTB session management |

## Operating Model

1. Read the matching prompt in this directory.
2. Also load `.claude/agents/CLAUDE.md` for shared safety, persistence, and artifact rules.
3. Spawn a Codex subagent using the recommended agent type.
4. Paste the prompt constraints that matter into the spawned mission. Do not assume the subagent has read local docs unless you tell it to.

## Prompting Rules

- Treat these files as Codex-native prompt templates, not passive reference docs.
- Preserve the repository security rules from `AGENTS.md`.
- Prefer `bounty_*` MCP tools or `bounty_intel/` for persistence.
- Keep write scopes narrow when using `worker` agents.
- Reuse `explorer` agents for repeated lookup tasks instead of respawning them.

## Example

```text
Spawn a `worker` subagent using `.agents/agents/pentester-executor.md`.
Mission:
- Objective: test reflected XSS on https://target/search
- Scope file: outputs/acme/scope.json
- Output dir: outputs/acme
- Skill folder: attacks/client-side/xss/
- Escalation: quickstart
```

## CLI Helper

Use the local dispatcher to inspect or render a Codex-ready spawn payload:

```bash
python -m bounty_intel agent list
python -m bounty_intel agent show --name pentester-executor
python -m bounty_intel agent dispatch \
  --name pentester-executor \
  --objective "Test reflected XSS on /search" \
  --scope-file outputs/acme/scope.json \
  --output-dir outputs/acme \
  --mission "Load the XSS quickstart guidance and test reflected XSS on the q parameter." \
  --json
```

Short aliases are also accepted, for example `executor`, `validator`, `orchestrator`, `intel`, or `htb`.

## Codex Delegation Procedure

When a Julius skill needs a subagent in Codex:

1. Run `python -m bounty_intel agent dispatch ... --json`.
2. Read `codex_agent_type`, `fork_context`, and `message` from the JSON output.
3. Call Codex `spawn_agent` with:
   - `agent_type = codex_agent_type`
   - `fork_context = true`
   - `message = message`
4. Reuse the same spawned agent when follow-up work belongs to the same role and context.
