## What changed

<!-- One or two sentences. What does this PR do? -->

## Why

<!-- The motivation. Issues are disabled on this repo, so the reasoning lives here. -->

## Type

<!-- Delete what does not apply. Must match the commit prefix. -->

feat / fix / docs / refactor / test / chore

## Scope

<!-- Delete what does not apply. -->

- [ ] Skill (`.claude/skills/`)
- [ ] Agent (`.claude/agents/`)
- [ ] AGENTS.md knowledge base
- [ ] Bounty Intel (`bounty_intel/`)
- [ ] Tooling (`tools/`)
- [ ] Documentation only

## Verification

<!-- What did you actually run? Paste the command, not a claim. -->

- [ ] Skills load and trigger as expected
- [ ] Python changes compile or pass their tests
- [ ] `validate_output_structure.sh` passes, if output formats changed

## Token budget

<!-- Required when CLAUDE.md or AGENTS.md changed. -->

- [ ] CLAUDE.md under 4 KB, AGENTS.md under 10 KB, combined under 15 KB (`wc -c CLAUDE.md AGENTS.md`)
- [ ] New reference material went to a skill doc or the DB, not to an always-loaded file

## Security

- [ ] No credentials, tokens, API keys, cookies or session values in the diff or in test fixtures
- [ ] No real target hostnames, client names or engagement data from non-public programs
- [ ] Any new offensive capability is authorized-testing only and non-destructive
