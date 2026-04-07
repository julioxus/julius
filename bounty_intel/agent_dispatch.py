"""Codex-native Julius agent dispatcher helpers.

Builds a stable mapping from Julius logical agent names to Codex-compatible
subagent settings and renders a mission prompt that can be fed into
`spawn_agent`.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_PROMPTS_DIR = REPO_ROOT / ".agents" / "agents"
SHARED_RULES_PATH = REPO_ROOT / ".claude" / "agents" / "CLAUDE.md"
KNOWLEDGE_BASE_PATH = REPO_ROOT / "AGENTS.md"


@dataclass(frozen=True)
class CodexAgentSpec:
    name: str
    codex_agent_type: str
    prompt_file: str
    description: str


AGENT_SPECS: dict[str, CodexAgentSpec] = {
    "pentester-orchestrator": CodexAgentSpec(
        name="pentester-orchestrator",
        codex_agent_type="default",
        prompt_file="pentester-orchestrator.md",
        description="Plan, batch, coordinate, and aggregate Julius testing work.",
    ),
    "pentester-executor": CodexAgentSpec(
        name="pentester-executor",
        codex_agent_type="worker",
        prompt_file="pentester-executor.md",
        description="Execute one bounded recon or exploitation mission.",
    ),
    "pentester-validator": CodexAgentSpec(
        name="pentester-validator",
        codex_agent_type="worker",
        prompt_file="pentester-validator.md",
        description="Validate one finding against evidence and raw artifacts.",
    ),
    "dom-xss-scanner": CodexAgentSpec(
        name="dom-xss-scanner",
        codex_agent_type="worker",
        prompt_file="dom-xss-scanner.md",
        description="Run JS-heavy DOM XSS verification with browser evidence.",
    ),
    "script-generator": CodexAgentSpec(
        name="script-generator",
        codex_agent_type="worker",
        prompt_file="script-generator.md",
        description="Generate validated helper scripts for Julius workflows.",
    ),
    "patt-fetcher": CodexAgentSpec(
        name="patt-fetcher",
        codex_agent_type="explorer",
        prompt_file="patt-fetcher.md",
        description="Retrieve focused payload intelligence for an attack class.",
    ),
    "hackerone-intel-fetcher": CodexAgentSpec(
        name="hackerone-intel-fetcher",
        codex_agent_type="explorer",
        prompt_file="hackerone-intel-fetcher.md",
        description="Fetch program or vulnerability intelligence from disclosed reports.",
    ),
    "skiller": CodexAgentSpec(
        name="skiller",
        codex_agent_type="worker",
        prompt_file="skiller.md",
        description="Create or refactor Julius skills under repo constraints.",
    ),
    "hackthebox": CodexAgentSpec(
        name="hackthebox",
        codex_agent_type="default",
        prompt_file="hackthebox.md",
        description="Manage an HTB session and delegate solving to Julius roles.",
    ),
}

AGENT_ALIASES: dict[str, str] = {
    "orchestrator": "pentester-orchestrator",
    "executor": "pentester-executor",
    "validator": "pentester-validator",
    "dom-xss": "dom-xss-scanner",
    "dom-xss-scanner": "dom-xss-scanner",
    "script": "script-generator",
    "script-generator": "script-generator",
    "payloads": "patt-fetcher",
    "patt": "patt-fetcher",
    "intel": "hackerone-intel-fetcher",
    "h1-intel": "hackerone-intel-fetcher",
    "skill": "skiller",
    "htb": "hackthebox",
}


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def get_agent_spec(name: str) -> CodexAgentSpec:
    canonical = AGENT_ALIASES.get(name, name)
    try:
        return AGENT_SPECS[canonical]
    except KeyError as exc:
        available = ", ".join(sorted(AGENT_SPECS))
        aliases = ", ".join(sorted(AGENT_ALIASES))
        raise KeyError(
            f"Unknown Julius agent: {name}. Available: {available}. Aliases: {aliases}"
        ) from exc


def list_agent_specs() -> list[CodexAgentSpec]:
    return [AGENT_SPECS[name] for name in sorted(AGENT_SPECS)]


def render_dispatch_payload(
    name: str,
    mission: str,
    context: str = "",
    objective: str = "",
    output_dir: str = "",
    scope_file: str = "",
    extra_instructions: str = "",
) -> dict[str, str | bool]:
    spec = get_agent_spec(name)
    prompt_path = AGENT_PROMPTS_DIR / spec.prompt_file

    base_prompt = _read_text(prompt_path)
    shared_rules = str(SHARED_RULES_PATH)
    knowledge_base = str(KNOWLEDGE_BASE_PATH)

    sections = [
        f"You are Julius agent `{spec.name}` running as a Codex `{spec.codex_agent_type}` subagent.",
        "Read and follow these repo instructions before executing the mission:",
        f"- Codex agent prompt: {prompt_path}",
        f"- Shared agent rules: {shared_rules}",
        f"- Security knowledge base: {knowledge_base}",
        "",
        "Base agent prompt:",
        base_prompt,
    ]

    mission_lines = ["Mission:"]
    if objective:
        mission_lines.append(f"- Objective: {objective}")
    if scope_file:
        mission_lines.append(f"- Scope file: {scope_file}")
    if output_dir:
        mission_lines.append(f"- Output dir: {output_dir}")
    if context:
        mission_lines.append("- Context:")
        mission_lines.append(context)
    mission_lines.append("- Task:")
    mission_lines.append(mission)
    if extra_instructions:
        mission_lines.append("- Extra instructions:")
        mission_lines.append(extra_instructions)

    sections.extend(["", "\n".join(mission_lines)])
    rendered_message = "\n".join(sections).strip() + "\n"

    return {
        "name": spec.name,
        "codex_agent_type": spec.codex_agent_type,
        "prompt_file": str(prompt_path),
        "description": spec.description,
        "fork_context": True,
        "message": rendered_message,
    }


def render_spawn_snippet(payload: dict[str, str | bool]) -> str:
    snippet = {
        "agent_type": payload["codex_agent_type"],
        "fork_context": payload["fork_context"],
        "message": payload["message"],
    }
    return json.dumps(snippet, indent=2, ensure_ascii=True)
