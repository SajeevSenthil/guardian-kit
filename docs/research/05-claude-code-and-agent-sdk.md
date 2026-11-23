# 05 - Claude Code project packaging and the Claude Agent SDK (Python)

Researched 2026-11-23 from the official docs (URLs in [Sources](#sources)).

How to read this file:

- **[verbatim]** = block copied from the official docs page named beside it.
- **[composed]** = written for this project out of documented fields/behaviours; every field name in it is documented, but the block itself does not appear in the docs. Run it before relying on it.
- **[unverified]** = not confirmed on a docs page read in this session. Check before use.

Docs facts that contradict common assumptions are collected in [section 9.1](#91-things-the-docs-say-that-people-get-wrong).

---

# PART A - Claude Code project packaging

Target layout for the repo:

```text
guardian-kit/
├── CLAUDE.md                     # team instructions, < 200 lines
├── CLAUDE.local.md               # personal, gitignored
├── .mcp.json                     # project MCP servers (committed)
└── .claude/
    ├── settings.json             # permissions, hooks, env (committed)
    ├── settings.local.json       # personal overrides (auto-gitignored by Claude Code)
    ├── rules/*.md                # optional path-scoped rules
    ├── agents/<name>.md          # subagents
    ├── skills/<name>/SKILL.md    # skills (= slash commands)
    ├── commands/*.md             # legacy slash commands (still work)
    └── hooks/*.sh                # hook scripts referenced from settings.json
```

## 1. CLAUDE.md

**Locations** (memory page):

| Scope | Path | Shared |
| :-- | :-- | :-- |
| Project | `./CLAUDE.md` or `./.claude/CLAUDE.md` | via git |
| Local | `./CLAUDE.local.md` (add to `.gitignore`) | no |
| User | `~/.claude/CLAUDE.md` | no |
| Managed | Linux/WSL `/etc/claude-code/CLAUDE.md`, macOS `/Library/Application Support/ClaudeCode/CLAUDE.md` | org |

**Loading**: Claude Code loads `CLAUDE.md` and `CLAUDE.local.md` from the working directory and every directory above it at launch; subdirectory files load on demand. Files are concatenated, not overridden, ordered root-down, and within a directory `CLAUDE.local.md` is appended after `CLAUDE.md`.

**Imports**: "CLAUDE.md files can import additional files using `@path/to/import` syntax." Relative paths resolve relative to the file containing the import, not the working directory. Maximum depth is **four hops**. Imports inside backticks or code fences are not expanded. Imports that resolve outside the working directory trigger a one-time approval dialog. Example from the docs:

```markdown
See @README for project overview and @package.json for available npm commands for this project.
```

Imports organise a file but do **not** reduce context cost: imported files load together with the importing file.

**Size and content**: "target under 200 lines per CLAUDE.md file. Longer files consume more context and reduce adherence." Test for each line: "Would removing this cause Claude to make mistakes?" If not, cut it.

| Include | Exclude |
| :-- | :-- |
| Bash commands Claude can't guess | Anything Claude can figure out by reading code |
| Code style rules that differ from defaults | Standard language conventions |
| Testing instructions and preferred test runners | Detailed API documentation (link instead) |
| Repository etiquette (branch naming, PR conventions) | Information that changes frequently |
| Architectural decisions specific to the project | Long explanations or tutorials |
| Dev environment quirks (required env vars) | File-by-file descriptions of the codebase |
| Common gotchas | "write clean code" |

Other useful facts:

- `/init` generates a starter file; `/context` confirms it loaded; `/doctor` proposes cuts.
- Block-level HTML comments (`<!-- ... -->`) are stripped before injection, so they cost no tokens.
- CLAUDE.md is advisory context, not enforcement. "To block an action regardless of what Claude decides, use a PreToolUse hook instead."
- CLAUDE.md is re-injected on every request, so it survives compaction; instructions given only in chat may not. You can add a section telling the compactor what to preserve.
- `AGENTS.md` is read only when there is no `CLAUDE.md` / `.claude/CLAUDE.md` / `CLAUDE.local.md` in the working directory or above (v2.1.277+). If the repo needs both, import it: `@AGENTS.md` inside `CLAUDE.md`.
- Auto memory (notes Claude writes itself) also loads every session: first 200 lines or 25KB.

**Path-scoped rules** `.claude/rules/*.md` **[verbatim]**:

```markdown
---
paths:
  - "src/api/**/*.ts"
---

# API Development Rules

- All API endpoints must include input validation
- Use the standard error response format
- Include OpenAPI documentation comments
```

Rules without `paths` load at launch with the same priority as `.claude/CLAUDE.md`.

## 2. Subagents: `.claude/agents/<name>.md`

**Priority when names collide** (highest first): managed settings, `--agents` CLI flag (session only), `.claude/agents/` (project), `~/.claude/agents/` (user), plugin `agents/`.

**Example [verbatim]** (sub-agents page):

```markdown
---
name: code-reviewer
description: Reviews code for quality and best practices
tools: Read, Glob, Grep
model: sonnet
---

You are a code reviewer. When invoked, analyze the code and provide
specific, actionable feedback on quality, security, and best practices.
```

The markdown body is the subagent's system prompt.

**Frontmatter fields**. Only `name` and `description` are required. Names are camelCase and must match exactly, otherwise Claude Code ignores them **without an error**.

| Field | Meaning |
| :-- | :-- |
| `name` (required) | Unique identifier, up to 256 chars, no colons |
| `description` (required) | Tells Claude when to delegate |
| `tools` | Allowlist of tools (comma-separated). Omit to inherit all tools available to subagents |
| `disallowedTools` | Denylist removed from the pool |
| `model` | `sonnet`, `opus`, `haiku`, `fable`, a full model ID, or `inherit` |
| `permissionMode` | Permission mode for the subagent |
| `maxTurns` | Max agentic turns |
| `skills` | Skills whose full content is preloaded at startup |
| `mcpServers` | MCP servers scoped to this subagent |
| `hooks` | Lifecycle hooks scoped to this subagent |
| `memory` | `user`, `project`, or `local` |
| `background` | Keep the subagent in the background when Claude would wait |
| `effort` | `low` through `max` |
| `isolation` | `worktree` runs it in a temporary git worktree |
| `color` | Display colour |
| `initialPrompt` | First user turn when run via `--agent` |
| `autoCompactWindow`, `omitClaudeMd`, `experimental` | Niche tuning |

**Model resolution** when `model` is omitted: per-invocation `model` parameter, frontmatter `model`, `CLAUDE_CODE_SUBAGENT_MODEL`, then the main conversation's model.

**Invocation**:

- Automatic: Claude matches the task to `description`. Nudge with "Use the test-runner subagent to fix failing tests."
- `@`-mention the subagent to guarantee it runs for that task.
- Whole session as that agent: `claude --agent code-reviewer`.
- `/agents` now only prints a reminder (it was a wizard in v2.1.197 and earlier); edit the files directly.
- New/edited files are picked up within seconds, except the first file in a brand-new `agents/` directory, which needs a session restart.

**Behaviour**:

- A subagent spawned from the main conversation **starts in the background by default**. Ask Claude to wait, or press Ctrl+B to background a running task.
- Subagents **can** spawn subagents, up to three layers below the main conversation (`CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH`, set `1` to turn nesting off). To stop one subagent from spawning, omit `Agent` from its `tools`.
- A subagent starts with a fresh context: it sees its own system prompt plus the prompt string Claude passes it, not the parent conversation. Only its final message returns.
- Built-ins: `Explore`, `Plan`, `general-purpose`, `statusline-setup`, `claude-code-guide`, `claude`.

## 3. Skills: `.claude/skills/<name>/SKILL.md`

**Locations**: enterprise (managed), personal `~/.claude/skills/<name>/SKILL.md`, project `.claude/skills/<name>/SKILL.md`, nested `<subdir>/.claude/skills/...`, plugin (`/plugin-name:skill-name`). Same name: enterprise beats personal beats project.

**Minimal example [verbatim]** (skills page):

```yaml
---
name: my-skill
description: What this skill does
disable-model-invocation: true
allowed-tools: Read Grep
---

Your skill instructions here...
```

**Frontmatter**. All fields optional; unknown names are ignored silently.

| Field | Purpose |
| :-- | :-- |
| `name` | Command name; defaults to the directory name |
| `description` | What it does and when to use it (this is what triggers it) |
| `when_to_use` | Extra trigger context appended to `description` |
| `argument-hint` | Autocomplete hint, e.g. `[issue-number]` |
| `arguments` | Named positional args for `$name` substitution |
| `disable-model-invocation` | `true` stops Claude auto-loading it |
| `user-invocable` | `false` hides it from the `/` menu |
| `allowed-tools` | Tools usable without prompts during the invoking turn |
| `disallowed-tools` | Tools removed while the skill is active |
| `model` | Model override for the turn |
| `effort` | Effort override |
| `context` | `fork` runs the skill in a subagent |
| `agent` | Subagent type when `context: fork` (default `general-purpose`) |
| `background` | With `fork`, `false` waits for the result |
| `hooks` | Hooks registered when the skill is invoked |
| `paths` | Globs limiting automatic activation |
| `shell` | `bash` (default) or `powershell` |
| `metadata`, `license`, `compatibility` | Informational |

**How skills trigger / invocation controls**:

| Frontmatter | You can invoke | Claude can invoke | In context |
| :-- | :-- | :-- | :-- |
| (default) | Yes (`/name`) | Yes | Description always; full skill on invocation |
| `disable-model-invocation: true` | Yes | No | Description not loaded; full skill on invocation |
| `user-invocable: false` | No | Yes | Description always; full skill on invocation |

`description` + `when_to_use` are truncated at **1,536 characters** in the skill listing, so put the key use case first. Use `disable-model-invocation: true` for anything with side effects (deploy, release, seeding demo data).

**Substitutions**: `$ARGUMENTS` (all args; if no placeholder is present they are appended as `ARGUMENTS: <value>`), `$ARGUMENTS[N]` or `$N` (0-based), `$name` (declared in `arguments`), `${CLAUDE_SESSION_ID}`, `${CLAUDE_SKILL_DIR}`. Escape a literal dollar with a backslash. `` !`cmd` `` runs a shell command before Claude sees the skill and inlines the output.

**Supporting files** (keep `SKILL.md` under 500 lines):

```text
my-skill/
├── SKILL.md           (required, overview and navigation)
├── reference.md       (loaded when needed)
├── examples.md        (loaded when needed)
└── scripts/helper.py  (executed, not loaded)
```

**`context: fork`**: the skill content becomes the prompt of a new subagent that does not see conversation history, so the skill must be a self-contained task. Forked skills run in the background unless `background: false`.

## 4. Custom slash commands: `.claude/commands/*.md`

Docs, verbatim: "**Custom commands have been merged into skills.** A file at `.claude/commands/deploy.md` and a skill at `.claude/skills/deploy/SKILL.md` both create `/deploy` and work the same way. Your existing `.claude/commands/` files keep working." If both exist with the same name, **the skill wins**.

So a command file is a single markdown file with the same frontmatter as a skill (`description`, `argument-hint`, `allowed-tools`, `model`, `disable-model-invocation`, ...) and the same `$ARGUMENTS` / `$1` substitutions. **[composed]**:

```markdown
---
description: Run the test suite for one pipeline stage and fix failures
argument-hint: [stage-name]
allowed-tools: Bash(uv run pytest *) Read Edit
disable-model-invocation: true
---

Run `uv run pytest tests/$ARGUMENTS -x -q`. Fix any failures, rerun until green,
then summarise what changed in 3 bullets.
```

Recommendation: write new ones as skills (they get a directory for supporting files); only keep `commands/` for one-file prompts.

Skills and commands work in `claude -p` too: put `/skill-name` in the prompt string.

## 5. `.claude/settings.json`

**Files and precedence** (highest first): managed settings; `--settings` on the command line; `.claude/settings.local.json`; `.claude/settings.json`; `~/.claude/settings.json`. List keys such as `permissions.allow` are **merged** across files, not overridden. Files are strict JSON (no comments, no trailing commas). Most edits hot-reload into a running session (including `permissions` and `hooks`); `model` and `effortLevel` are read only at session start. Check with `/status`; diagnose with `claude doctor`.

### 5.1 Permission rules

"Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome, and rule specificity doesn't change the order." An allow rule cannot carve an exception out of a deny rule.

Syntax is `Tool` or `Tool(specifier)`.

**[verbatim]** (permissions page):

```json
{
  "permissions": {
    "allow": [
      "Bash(npm run *)",
      "Bash(git commit *)"
    ],
    "deny": [
      "Bash(git push *)"
    ]
  }
}
```

**Bash wildcard rules**:

- The documented form is space-star: `Bash(git push *)`. The legacy colon form is still valid: "The `:*` suffix is an equivalent way to write a trailing wildcard, so `Bash(ls:*)` matches the same commands as `Bash(ls *)`." It is "only recognized at the end of a pattern". So `Bash(npm publish:*)`, `Bash(git push:*)`, `Bash(docker push:*)` all work; the permission dialog itself now writes the space form.
- A trailing ` *` also matches the bare command: `Bash(ls *)` matches `ls` and `ls -la` but not `lsof`. `Bash(ls*)` (no space) also matches `lsof`.
- Compound commands are split on `&&`, `||`, `;`, `|`, `|&`, `&`, newlines. An allow rule must match each subcommand; a deny/ask rule fires if **any** subcommand matches (including inside `$()` or a `for` body).
- **Bash deny rules are not a security boundary.** `Bash(git push *)` stops `git push origin main` but not `git -C . push origin main`, `git -c push.default=current push origin main`, or `git 'push' origin main`. `Bash(curl *)` does not stop `/usr/bin/curl ...` or `sh -c 'curl ...'`. Back important denies with a PreToolUse hook (5.2) and, for pushes, with missing credentials.

**Other rule forms**:

| Rule | Matches |
| :-- | :-- |
| `Read(./.env)`, `Read(./.env.*)` | Path relative to the rule's source |
| `Read(//abs/path/**)` | Absolute filesystem path (double slash) |
| `Read(~/Documents/*.pdf)` | Home-relative |
| `Edit(/src/**)` | Single leading slash anchors at the settings source / project, **not** filesystem root |
| `Edit(path)` | Governs every file-writing tool incl. `Write`, `NotebookEdit`; a `Write(path)` rule is never matched by file permission checks |
| `WebFetch(domain:example.com)` | Hostname only; add `WebFetch(domain:*.example.com)` for subdomains |
| `mcp__server` or `mcp__server__*` | Every tool of that MCP server |
| `mcp__server__tool` | One MCP tool |
| `Agent(model:opus)`, `Agent(isolation:worktree)` | Agent calls by parameter |

Allow-side globs are only accepted after a literal `mcp__<server>__` prefix; `"*"` or `"mcp__*"` in `allow` is skipped. Deny accepts `"mcp__*"` and `"*"`.

Other keys under `permissions`: `defaultMode` (`auto` and `bypassPermissions` do not take effect from project or local settings), `additionalDirectories`, `disableBypassPermissionsMode: "disable"`, `disableAutoMode: "disable"`.

Trust caveat: in a committed `.claude/settings.json`, `deny` and `ask` rules apply immediately, but `allow` rules, `additionalDirectories` and most `env` values apply only after each teammate trusts the folder.

### 5.2 Hooks

**Schema [verbatim]** (hooks reference):

```json
{
  "hooks": {
    "<EventName>": [
      {
        "matcher": "<matcher pattern>",
        "hooks": [
          {
            "type": "command",
            "command": "<shell command or executable>",
            "args": [],
            "if": "<permission-rule filter>",
            "timeout": 30,
            "async": false,
            "shell": "bash",
            "statusMessage": "Checking..."
          }
        ]
      }
    ]
  }
}
```

- Handler `type`: `command`, `http`, `mcp_tool`, `prompt`, `agent` (experimental).
- `timeout` is in **seconds**. Defaults: 600s for `command`/`http`/`mcp_tool`, 30s for `prompt`, 60s for `agent`.
- `matcher`: `"*"`, `""` or omitted matches all. Only letters/digits/`_`/`-`/space/`,`/`|` means exact match or a list (`Edit|Write`). Any other character makes it an unanchored JavaScript regex (`mcp__memory__.*`). Matchers match tool **names**, never arguments. `Stop` ignores matchers.
- `if`: exactly one permission rule, e.g. `"Bash(git *)"`; evaluated on tool events only.
- Events: SessionStart, Setup, UserPromptSubmit, UserPromptExpansion, PreToolUse, PermissionRequest, PermissionDenied, PostToolUse, PostToolUseFailure, PostToolBatch, Notification, MessageDisplay, SubagentStart, SubagentStop, TaskCreated, TaskCompleted, Stop, StopFailure, TeammateIdle, InstructionsLoaded, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreCompact, PostCompact, PreModelSwitch, PostModelSwitch, Elicitation, ElicitationResult, SessionEnd.
- Env available to hook commands: `$CLAUDE_PROJECT_DIR`, `$CLAUDE_EFFORT`, `$CLAUDE_CODE_REMOTE`, plus the inherited environment.

**Exit codes**:

| Exit | Meaning |
| :-- | :-- |
| `0` | Success. Stdout is parsed as JSON if it is a JSON object. Claude never sees stderr |
| `2` | Blocking error on events that can block. **Stderr is fed to Claude as the reason** |
| other | Non-blocking error; the action proceeds |

**PreToolUse stdin [verbatim]**:

```json
{
  "session_id": "abc123",
  "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "scratchpad_dir": "/tmp/claude-1000/-home-user-my-project/abc123/scratchpad",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "npm test",
    "description": "Run test suite",
    "timeout": 120000,
    "run_in_background": false
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

**PreToolUse output [verbatim]**:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by hook"
  }
}
```

`permissionDecision` is `allow`, `deny`, `ask` or `defer`. `updatedInput` and `additionalContext` also live inside `hookSpecificOutput`. Priority across hooks and rules: deny > defer > ask > allow. A hook `allow` does not skip deny/ask rules.

**Stop / PostToolUse output**: top-level `{"decision": "block", "reason": "..."}`. On `Stop` this keeps Claude working (use it to force "tests must pass before you stop"); guard against loops with the `stop_hook_active` input field. On `PostToolUse` the tool has already run, so `block` only feeds the reason back.

**Working example: block publish/push commands.** The docs' own example (block `rm -rf`) **[verbatim]**:

`.claude/settings.json`

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(rm *)",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/block-rm.sh",
            "args": []
          }
        ]
      }
    ]
  }
}
```

`.claude/hooks/block-rm.sh` (needs `jq`; `chmod +x`)

```bash
#!/bin/bash
# .claude/hooks/block-rm.sh
COMMAND=$(jq -r '.tool_input.command')

if echo "$COMMAND" | grep -q 'rm -rf'; then
  jq -n '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "Destructive command blocked by hook"
    }
  }'
else
  exit 0  # no decision; normal permission flow applies
fi
```

Adapted for this project **[composed]**: catches the spellings a deny rule misses, because it greps the whole command text. The script was run standalone against sample inputs on 2026-11-23: it blocks `git push origin main`, `git -C . push origin main`, `git -c push.default=current push`, `git 'push' origin`, `cd x && npm publish`, `docker push img`, and lets through `git status`, `git log --grep push`, `git commit -m 'add push button'`, `git stash push`. It was not exercised inside a live Claude Code session. Needs `jq` and `chmod +x`.

`.claude/hooks/block-publish.sh`

```bash
#!/bin/bash
# Blocks git push / npm publish / docker push however they are spelled.
COMMAND=$(jq -r '.tool_input.command')

if echo "$COMMAND" | grep -Eq '(^|[^[:alnum:]_-])(git([[:space:]]+-[^[:space:]]+([[:space:]]+[^[:space:]-][^[:space:]]*)?)*[[:space:]]+.?push|npm[[:space:]]+publish|docker[[:space:]]+push|twine[[:space:]]+upload|uv[[:space:]]+publish)'; then
  echo "Blocked: publishing/pushing is a human-only step in this repo. Ask the user to run it." >&2
  exit 2   # exit 2 = block; stderr is shown to Claude as the reason
fi
exit 0
```

### 5.3 Complete project `settings.json` **[composed]**

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "permissions": {
    "allow": [
      "Bash(uv run pytest *)",
      "Bash(uv run ruff *)",
      "Bash(git status *)",
      "Bash(git diff *)",
      "Bash(git log *)",
      "Bash(git add *)",
      "Bash(git commit *)"
    ],
    "ask": [
      "Bash(uv add *)",
      "Bash(docker *)"
    ],
    "deny": [
      "Bash(npm publish:*)",
      "Bash(git push:*)",
      "Bash(docker push:*)",
      "Bash(curl *)",
      "Read(./.env)",
      "Read(./.env.*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/block-publish.sh",
            "timeout": 10
          }
        ]
      }
    ]
  },
  "env": {
    "GUARDIAN_ENV": "dev"
  }
}
```

Notes:

- `"ask": ["Bash(docker *)"]` plus `"deny": ["Bash(docker push:*)"]` is fine: deny is evaluated first.
- `env` **[unverified format]**: the settings page describes "an `env` block inside a settings file" as an ordinary key but the page read here shows no example. The long-standing format is an object of string to string, as above; confirm at `settings-reference#env`. Never commit secrets there; `ANTHROPIC_API_KEY` belongs in the shell or an untracked `.env`.
- `$schema` gives editor validation; it can lag new keys.

## 6. MCP, modes and sprint workflow

### 6.1 `.mcp.json` (project scope, committed)

**[verbatim shapes]** (mcp page). HTTP:

```json
{
  "mcpServers": {
    "api-server": {
      "type": "http",
      "url": "${API_BASE_URL:-https://api.example.com}/mcp",
      "headers": {
        "Authorization": "Bearer ${API_KEY}"
      }
    }
  }
}
```

Stdio (an entry with `command` and no `type` is read as stdio):

```json
{
  "mcpServers": {
    "database-tools": {
      "command": "/path/to/server",
      "args": ["--config", "/path/to/config.json"],
      "env": {
        "DB_URL": "${DB_URL}"
      }
    }
  }
}
```

- Expansion `${VAR}` and `${VAR:-default}` is allowed in `command`, `args`, `env`, `url`, `headers`.
- In remote `url`/`headers`, credential-like variables such as `ANTHROPIC_API_KEY` read as **empty**; copy the value into a differently named variable.
- Interactive sessions prompt before using `.mcp.json` servers (`claude mcp reset-project-choices` to redo). **`claude -p` and Agent SDK runs load project servers without prompting.**
- `MCP_TIMEOUT` (startup, ms), `MCP_TOOL_TIMEOUT`, `MAX_MCP_OUTPUT_TOKENS` (default 25,000). `/mcp` shows status and handles OAuth.

**CLI**:

```bash
claude mcp add --transport http <name> <url> [--header "Authorization: Bearer ..."]
claude mcp add [--env KEY=val] --transport stdio <name> -- <command> [args...]
claude mcp add-json <name> '<json>'
claude mcp list | get <name> | remove <name>
# --scope local (default, ~/.claude.json) | project (.mcp.json) | user
# --transport sse is deprecated
```

### 6.2 Servers worth adding for this build

| Server | Line | Status |
| :-- | :-- | :-- |
| GitHub | `claude mcp add --transport http github https://api.githubcopilot.com/mcp/ --header "Authorization: Bearer YOUR_GITHUB_PAT"` | verbatim from the Claude Code MCP page |
| Sentry | `claude mcp add --transport http sentry https://mcp.sentry.dev/mcp` | verbatim |
| Postgres (DBHub) | `claude mcp add --transport stdio db -- npx -y @bytebase/dbhub --dsn "postgresql://readonly:pass@host:5432/db"` | verbatim |
| Playwright (UI testing) | `claude mcp add --scope project --transport stdio playwright -- npx -y @playwright/mcp@latest` | **[unverified]** not on the Claude Code docs page; package name is from the Playwright MCP project, check its README |
| Context7 (library docs) | `claude mcp add --scope project --transport http context7 https://mcp.context7.com/mcp` | **[unverified]** not on the Claude Code docs page; check Context7's README |

Advice from the best-practices page: prefer CLI tools (`gh`, `aws`, ...) over MCP where one exists; they are "the most context-efficient way to interact with external services". For GitHub on a 2-day sprint, `gh` is usually enough. Tool search is on by default, so idle MCP servers cost little context.

### 6.3 Modes and commands

| Need | How |
| :-- | :-- |
| Plan mode | `Shift+Tab` until the status bar shows `plan mode on`, or `claude --permission-mode plan`. `Ctrl+G` opens the plan in your editor |
| Headless | `claude -p "prompt"`; add `--bare` for reproducible runs (skips hooks, skills, commands, subagents, plugins, MCP, auto memory, CLAUDE.md) |
| Headless output | `--output-format text\|json\|stream-json`; `--json-schema '<schema>'` puts the result in `structured_output` |
| Headless permissions | `--allowedTools "Read,Edit,Bash(git diff *)"`, `--permission-mode dontAsk\|acceptEdits\|auto`, `--permission-prompts none` (v2.1.259+) |
| Continue | `claude --continue`, `claude --resume <session-id>`; name sessions with `/rename` |
| Reset context | `/clear` between unrelated tasks |
| Compact | `/compact <instructions>`, e.g. `/compact Focus on the API changes` |
| Side question | `/btw` (answer never enters history) |
| Rewind | `Esc` `Esc` on an empty prompt, or `/rewind` |
| Stop Claude | `Esc` (context preserved) |
| Inspect | `/context`, `/status`, `/hooks`, `/mcp`, `/permissions` |

Headless examples **[verbatim]**:

```bash
claude -p "Find and fix the bug in auth.py" --allowedTools "Read,Edit,Bash"
claude --bare -p "Summarize README.md" --allowedTools "Read"
claude -p "Summarize this project" --output-format json | jq -r '.result'
cat build-error.txt | claude -p 'concisely explain the root cause of this build error' > output.txt
session_id=$(claude -p "Start a review" --output-format json | jq -r '.session_id')
claude -p "Continue that review" --resume "$session_id"
```

Headless caveats: without `--bare`, a `-p` run executes the project's hooks and connects `.mcp.json` servers with no trust dialog. `--bare` needs `ANTHROPIC_API_KEY` (it never reads the subscription login). From v2.1.302 a `-p` run starts in Manual mode, where a call that needs approval is denied.

**Checkpoints / rewind**: every prompt that starts a turn creates a checkpoint (100 most recent kept). Rewind menu: Restore code and conversation / Restore conversation / Restore code / Summarize from here / Summarize up to here. Limits: files changed by **Bash commands** (`rm`, `mv`, `cp`) are not tracked; edits by background subagents are not restored; external edits are not tracked. "Not a replacement for version control."

**Parallel work**:

- Git worktrees: separate CLI sessions in isolated checkouts so edits do not collide (`https://code.claude.com/docs/en/worktrees`). The `claude --worktree <name>` flag is **[unverified]** here (page not read); plain `git worktree add ../gk-ui -b ui && cd ../gk-ui && claude` always works. `.claude/settings.local.json` is shared with the main checkout; a gitignored `CLAUDE.local.md` is not.
- Subagent frontmatter `isolation: worktree` runs a subagent in a temporary worktree.
- `/batch <instruction>` splits a change across 5 to 30 subagents, each in its own worktree.
- `claude agents` (agent view, research preview) dispatches background sessions.
- Fan-out script **[verbatim]**:

```bash
for file in $(cat files.txt); do
  claude -p "Migrate $file from Python 2 to Python 3. Return OK or FAIL." \
    --allowedTools "Edit,Bash(git commit *)" \
    --permission-mode dontAsk
done
```

### 6.4 Two-day sprint playbook

1. **Hour 0**: commit `CLAUDE.md` (run/test/lint commands, architecture in 10 lines, "never push"), `.claude/settings.json` (5.3), the block hook, `.mcp.json`. Everyone gets the same guardrails.
2. **Give Claude a check it can run** for every task (a pytest target, a script that diffs output against a fixture). This is the docs' number-one lever. Consider a `Stop` hook that blocks until `uv run pytest -q` passes.
3. **Plan mode for anything touching several files**; skip it when you could describe the diff in one sentence.
4. **One task per session.** `/clear` between unrelated tasks. After two failed corrections on the same issue, `/clear` and write a better prompt.
5. **Push research into subagents** ("use subagents to investigate X") so file reads do not fill the main context.
6. **Write a SPEC.md, then execute it in a fresh session.** The interview prompt in the best-practices page works well for this.
7. **Writer/reviewer**: a second session (or subagent) reviews the diff with fresh context. Tell it to flag only correctness gaps.
8. **One worktree per person/feature**; merge often. Humans do the `git push`.
9. **Commit before risky asks.** Rewind does not undo Bash-side changes.
10. Keep `CLAUDE.md` pruned. If Claude ignores a rule, the file is too long, or the rule should be a hook.

---

# PART B - Claude Agent SDK (Python) for the runtime

## 7. Quickstart

```bash
uv init && uv add claude-agent-sdk
# or
python3 -m venv .venv && source .venv/bin/activate && pip install claude-agent-sdk
export ANTHROPIC_API_KEY=your-api-key
```

- **Python 3.10+**.
- **Claude Code CLI / Node**: "Both the TypeScript and Python SDKs bundle a native Claude Code binary, so most installs need no separate Claude Code install." Node is not required for the Python SDK. Exception: if pip installs the source distribution instead of a platform wheel (e.g. ARM64 Windows) no binary is bundled; install Claude Code natively and the SDK finds it on `PATH`, or set `ClaudeAgentOptions(cli_path=...)`.
- **Architecture consequence**: the SDK launches that binary as a **subprocess** per `query()` / `ClaudeSDKClient`. In a container, install the SDK during the image build so the bundled binary matches the image architecture/libc.
- **Auth**: `ANTHROPIC_API_KEY`. The SDK "doesn't load `.env` files automatically" - call `dotenv.load_dotenv()` yourself before using it. Alternatives: `CLAUDE_CODE_USE_BEDROCK=1`, `CLAUDE_CODE_USE_VERTEX=1`, `CLAUDE_CODE_USE_FOUNDRY=1`, or `CLAUDE_CODE_USE_ANTHROPIC_AWS=1` + `ANTHROPIC_AWS_WORKSPACE_ID`.
- **Do not ship claude.ai login**: "Unless previously approved, Anthropic does not allow third party developers to offer claude.ai login or rate limits for their products, including agents built on the Claude Agent SDK."

## 8. Reference and examples

### 8.1 `query()` with `ClaudeAgentOptions`

Signature **[verbatim]**:

```python
async def query(
    *,
    prompt: str | AsyncIterable[dict[str, Any]],
    options: ClaudeAgentOptions | None = None,
    transport: Transport | None = None
) -> AsyncIterator[Message]
```

Each call starts fresh with no memory unless you pass `continue_conversation=True` or `resume`.

Quickstart example **[verbatim]**:

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, ResultMessage


async def main():
    # Agentic loop: streams messages as Claude works
    async for message in query(
        prompt="Review utils.py for bugs that would cause crashes. Fix any issues you find.",
        options=ClaudeAgentOptions(
            allowed_tools=["Read", "Edit", "Glob"],  # Auto-approve these tools
            permission_mode="acceptEdits",  # Auto-approve file edits
        ),
    ):
        # Print human-readable output
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if hasattr(block, "text"):
                    print(block.text)  # Claude's reasoning
                elif hasattr(block, "name"):
                    print(f"Tool: {block.name}")  # Tool being called
        elif isinstance(message, ResultMessage):
            print(f"Done: {message.subtype}")  # Final result


asyncio.run(main())
```

`ClaudeAgentOptions` **[verbatim, full dataclass]**:

```python
@dataclass
class ClaudeAgentOptions:
    tools: list[str] | ToolsPreset | None = None
    allowed_tools: list[str] = field(default_factory=list)
    system_prompt: str | SystemPromptPreset | SystemPromptCustom | SystemPromptFile | None = None
    mcp_servers: dict[str, McpServerConfig] | str | Path = field(default_factory=dict)
    strict_mcp_config: bool = False
    permission_mode: PermissionMode | None = None
    continue_conversation: bool = False
    resume: str | None = None
    session_id: str | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    disallowed_tools: list[str] = field(default_factory=list)
    model: str | None = None
    fallback_model: str | None = None
    betas: list[SdkBeta] = field(default_factory=list)
    output_format: dict[str, Any] | None = None
    permission_prompt_tool_name: str | None = None
    cwd: str | Path | None = None
    cli_path: str | Path | None = None
    settings: str | None = None
    add_dirs: list[str | Path] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    extra_args: dict[str, str | None] = field(default_factory=dict)
    max_buffer_size: int | None = None
    debug_stderr: Any = sys.stderr  # Deprecated
    stderr: Callable[[str], None] | None = None
    can_use_tool: CanUseTool | None = None
    hooks: dict[HookEvent, list[HookMatcher]] | None = None
    user: str | None = None
    include_partial_messages: bool = False
    include_hook_events: bool = False
    forward_subagent_text: bool = False
    verbatim_prompts: bool = False
    fork_session: bool = False
    resume_session_at: str | None = None
    resume_drops_turn: str | None = None
    agents: dict[str, AgentDefinition] | None = None
    setting_sources: list[SettingSource] | None = None
    skills: list[str] | Literal["all"] | None = None
    sandbox: SandboxSettings | None = None
    plugins: list[SdkPluginConfig] = field(default_factory=list)
    max_thinking_tokens: int | None = None  # Deprecated: use thinking instead
    thinking: ThinkingConfig | None = None
    effort: EffortLevel | None = None
    enable_file_checkpointing: bool = False
    session_store: SessionStore | None = None
    session_store_flush: SessionStoreFlushMode = "batched"
    load_timeout_ms: int = 60_000
    task_budget: TaskBudget | None = None
```

`system_prompt`: a plain string for a custom prompt; `{"type": "preset", "preset": "claude_code"}` (optionally with `"append"`) for Claude Code's prompt; `{"type": "file", "path": "..."}` for a large prompt on disk. With no `system_prompt`, Claude Code's full system prompt is **not** built.

`env` is **merged** on top of the inherited environment in Python (the TypeScript SDK replaces it).

### 8.2 `ClaudeSDKClient` (multi-turn, interrupts, dynamic mode)

Methods **[verbatim]**:

```python
class ClaudeSDKClient:
    def __init__(self, options: ClaudeAgentOptions | None = None, transport: Transport | None = None)
    async def connect(self, prompt: str | AsyncIterable[dict] | None = None) -> None
    async def query(self, prompt: str | AsyncIterable[dict], session_id: str = "default") -> None
    async def receive_messages(self) -> AsyncIterator[Message]
    async def receive_response(self) -> AsyncIterator[Message]
    async def interrupt(self) -> None
    async def set_permission_mode(self, mode: PermissionMode) -> None
    async def set_model(self, model: str | None = None) -> None
    async def rewind_files(self, user_message_id: str) -> None
    async def get_mcp_status(self) -> McpStatusResponse
    async def reconnect_mcp_server(self, server_name: str) -> None
    async def toggle_mcp_server(self, server_name: str, enabled: bool) -> None
    async def stop_task(self, task_id: str) -> None
    async def get_server_info(self) -> dict[str, Any] | None
    async def disconnect(self) -> None
```

Example **[verbatim]** (permissions page):

```python
import asyncio
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions


async def main():
    async with ClaudeSDKClient(
        options=ClaudeAgentOptions(
            permission_mode="default",  # Start in default mode
        )
    ) as client:
        await client.query("Help me refactor this code")

        # Change mode dynamically mid-session
        await client.set_permission_mode("acceptEdits")

        # Process messages with the new permission mode
        async for message in client.receive_response():
            if hasattr(message, "result"):
                print(message.result)


asyncio.run(main())
```

Use `query()` for one-shot pipeline stages; use `ClaudeSDKClient` when a stage needs follow-up turns, `interrupt()`, or session continuity (it handles session IDs automatically). After `interrupt()` you must drain the buffer with `receive_response()` before reading the next reply.

### 8.3 Custom tools: `@tool` + `create_sdk_mcp_server`

Signatures **[verbatim]**:

```python
def tool(
    name: str,
    description: str,
    input_schema: type | dict[str, Any],
    annotations: ToolAnnotations | None = None
) -> Callable[[Callable[[Any], Awaitable[dict[str, Any]]]], SdkMcpTool[Any]]

def create_sdk_mcp_server(
    name: str,
    version: str = "1.0.0",
    tools: list[SdkMcpTool[Any]] | None = None
) -> McpSdkServerConfig
```

Example **[verbatim]** (custom-tools page, two blocks joined):

```python
from typing import Any
import httpx
from claude_agent_sdk import tool, create_sdk_mcp_server


# Define a tool: name, description, input schema, handler
@tool(
    "get_temperature",
    "Get the current temperature at a location",
    {"latitude": float, "longitude": float},
)
async def get_temperature(args: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": args["latitude"],
                "longitude": args["longitude"],
                "current": "temperature_2m",
                "temperature_unit": "fahrenheit",
            },
        )
        data = response.json()

    # Return a content array - Claude sees this as the tool result
    return {
        "content": [
            {
                "type": "text",
                "text": f"Temperature: {data['current']['temperature_2m']}°F",
            }
        ]
    }


# Wrap the tool in an in-process MCP server
weather_server = create_sdk_mcp_server(
    name="weather",
    version="1.0.0",
    tools=[get_temperature],
)
```

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage


async def main():
    options = ClaudeAgentOptions(
        mcp_servers={"weather": weather_server},
        allowed_tools=["mcp__weather__get_temperature"],
    )

    async for message in query(
        prompt="What's the temperature in San Francisco?",
        options=options,
    ):
        # ResultMessage is the final message after all tool calls complete
        if isinstance(message, ResultMessage) and message.subtype == "success":
            print(message.result)


asyncio.run(main())
```

Rules:

- **Naming**: `mcp__{server_name}__{tool_name}`, where `{server_name}` is the **key in `mcp_servers`** (not the `name=` argument). Wildcard: `mcp__weather__*`.
- The server runs **in-process**; handlers are ordinary `async def` in your app and can touch your app state.
- Schema: the dict form `{"latitude": float}` makes every key required and has no enums. For enums/optional/nested, pass a full JSON Schema dict (`{"type": "object", "properties": {...}, "required": [...]}`).
- Return `{"content": [{"type": "text", "text": "..."}]}`. Signal failure with `"is_error": True` (Python spelling; TypeScript is `isError`). An uncaught exception does not stop the loop; it reaches Claude as the raw `str(e)`.
- The Python `@tool` decorator forwards **only `content` and `is_error`**; `structuredContent` is dropped.
- Custom tools run **sequentially** unless marked read-only: `annotations=ToolAnnotations(readOnlyHint=True)`.
- Tool search is on by default and defers MCP tool schemas, so the stream may show a `ToolSearch` call before your tool. Disable with `env={"ENABLE_TOOL_SEARCH": "false"}` if a stage has few tools.

### 8.4 Restricting an agent to only its tools

Two layers (custom-tools page):

| Option | Layer | Effect |
| :-- | :-- | :-- |
| `tools=["Read", "Grep"]` | Availability | Only the listed built-ins are in context. MCP tools are unaffected |
| `tools=[]` | Availability | All built-ins removed. Claude can only use your MCP tools |
| `allowed_tools=[...]` | Permission | Listed tools run without a prompt. **Unlisted tools remain available** and go through the permission flow |
| `disallowed_tools=["Bash"]` | Both | Bare name removes the tool from context |
| `disallowed_tools=["Bash(rm *)"]` | Permission | Tool stays visible; matching calls denied in every mode, including `bypassPermissions` |
| `disallowed_tools=["*"]` / `["mcp__*"]` | Availability | Removes every tool / every MCP tool |

Docs warnings, verbatim: "`allowed_tools` does not constrain `bypassPermissions`. ... Setting `allowed_tools=["Read"]` alongside `permission_mode="bypassPermissions"` still approves every tool, including `Bash`, `Write`, and `Edit`."

Locked-down stage recipe **[composed]**:

```python
options = ClaudeAgentOptions(
    system_prompt="You are the triage agent. Use only the triage tools.",
    tools=[],                                   # no built-in tools at all
    mcp_servers={"triage": triage_server},      # only our in-process tools
    allowed_tools=["mcp__triage__*"],           # pre-approve them
    permission_mode="dontAsk",                  # anything else that would prompt is denied
    setting_sources=[],                         # ignore ~/.claude and the repo's .claude/
    max_turns=8,
    max_budget_usd=0.50,
    model="sonnet",
)
```

Caveats: in `dontAsk`, calls that need no approval in default mode still run (file reads in the working directory, `Agent`), which is why `tools=[]` matters. `strict_mcp_config` exists on the dataclass (its description was not in the portion of the reference read; **[unverified]** that `True` ignores `.mcp.json`). With `setting_sources=[]` the project MCP file is not loaded as a setting source in any case - verify with `SystemMessage` subtype `init`, whose `data` lists tools and MCP servers.

Evaluation order: **Hooks, then deny rules, then ask rules, then permission mode, then allow rules, then `can_use_tool`.**

### 8.5 Structured output

Shape: `output_format={"type": "json_schema", "schema": {...}}`. Read `ResultMessage.structured_output`.

Pydantic example **[verbatim]**:

```python
import asyncio
from pydantic import BaseModel
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage


class Step(BaseModel):
    step_number: int
    description: str
    estimated_complexity: str  # 'low', 'medium', 'high'


class FeaturePlan(BaseModel):
    feature_name: str
    summary: str
    steps: list[Step]
    risks: list[str]


async def main():
    try:
        async for message in query(
            prompt="Plan how to add dark mode support to a React app. Break it into implementation steps.",
            options=ClaudeAgentOptions(
                output_format={
                    "type": "json_schema",
                    "schema": FeaturePlan.model_json_schema(),
                }
            ),
        ):
            if (
                isinstance(message, ResultMessage)
                and not message.is_error
                and message.structured_output
            ):
                # Validate and get fully typed result
                plan = FeaturePlan.model_validate(message.structured_output)
                print(f"Feature: {plan.feature_name}")
                print(f"Summary: {plan.summary}")
                for step in plan.steps:
                    print(
                        f"{step.step_number}. [{step.estimated_complexity}] {step.description}"
                    )
    except Exception as error:
        # A single-shot query() raises after yielding an error result, such as
        # error_max_structured_output_retries; see the Error handling section.
        print(f"Session ended with an error: {error}")


asyncio.run(main())
```

Rules:

- Schemas are validated as **JSON Schema draft-07**; a schema declaring a newer draft is rejected. An invalid schema fails the run at startup.
- Supported: basic types, `enum`, `const`, `required`, nested objects, `$ref`. `format` is accepted but not enforced.
- Mechanism: Claude Code adds a tool named `StructuredOutput`; the agent calls it, possibly several times if validation fails. **Hide `StructuredOutput` tool calls in your UI/logs** and read the data only from `ResultMessage.structured_output`.
- **`subtype == "success"` does not guarantee data.** Treat as failure when `is_error` is `True` or `structured_output` is `None`. Failure subtype: `error_max_structured_output_retries` (check `message.errors`).
- Structured output never streams; it only appears on the final result.
- Keep schemas shallow; make fields optional when the task may not have the data.

### 8.6 Subagents via `agents={...}`

`AgentDefinition` **[verbatim]**:

```python
@dataclass
class AgentDefinition:
    description: str
    prompt: str
    tools: list[str] | None = None
    disallowedTools: list[str] | None = None
    model: str | None = None
    skills: list[str] | None = None
    memory: Literal["user", "project", "local"] | None = None
    mcpServers: list[str | dict[str, Any]] | None = None
    initialPrompt: str | None = None
    maxTurns: int | None = None
    background: bool | None = None
    effort: EffortLevel | int | None = None
    permissionMode: PermissionMode | None = None
```

Example **[verbatim]** (the first example on the subagents page):

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions, AgentDefinition


async def main():
    async for message in query(
        prompt="Review the authentication module for security issues",
        options=ClaudeAgentOptions(
            # Auto-approve these tools
            allowed_tools=["Read", "Grep", "Glob", "Agent", "Bash(npm test *)"],
            agents={
                "code-reviewer": AgentDefinition(
                    # description tells Claude when to use this subagent
                    description="Expert code review specialist. Use for quality, security, and maintainability reviews.",
                    # prompt defines the subagent's behavior and expertise
                    prompt="""You are a code review specialist with expertise in security, performance, and best practices.

When reviewing code:
- Identify security vulnerabilities
- Check for performance issues
- Verify adherence to coding standards
- Suggest specific improvements

Be thorough but concise in your feedback.""",
                    # tools restricts what the subagent can do (read-only here)
                    tools=["Read", "Grep", "Glob"],
                    # model overrides the default model for this subagent
                    model="sonnet",
                ),
                "test-runner": AgentDefinition(
                    description="Runs and analyzes test suites. Use for test execution and coverage analysis.",
                    prompt="""You are a test execution specialist. Run tests and provide clear analysis of results.

Focus on:
- Running test commands
- Analyzing test output
- Identifying failing tests
- Suggesting fixes for failures""",
                    # Bash access lets this subagent run test commands
                    tools=["Bash", "Read", "Grep"],
                ),
            },
        ),
    ):
        if hasattr(message, "result"):
            print(message.result)


asyncio.run(main())
```

Facts:

- Claude invokes subagents through the **`Agent`** tool. It appears as `"Agent"` in `tool_use` blocks but as `"Task"` in the `system:init` tools list; match both names when detecting it (`block.input.get("subagent_type")`).
- Messages from inside a subagent carry `parent_tool_use_id`.
- **Default is background**: the Agent tool result has `status: "async_launched"` and the report arrives in a later turn. Claude waits only when its next action needs the report. Say "run X and wait for it" in the prompt to force waiting. `background=True` keeps it in the background.
- `AgentDefinition.tools` lists what is available; "listing one doesn't pre-approve it".
- The only parent-to-subagent channel is the Agent tool's prompt string. The subagent does not get the parent's system prompt or history.
- Programmatic agents override filesystem agents of the same name. Without any definitions Claude can still spawn the built-in `general-purpose` agent (`CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS=1` removes it).
- Caps: `env={"CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH": "1", "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS": "5"}` (defaults 3 and 20); `max_budget_usd` covers subagent spend.
- Subagent permission mode is inherited from the parent; `permissionMode` on the definition applies only when the parent is in `default`, `dontAsk` or `plan`.
- `AskUserQuestion` is not available inside subagents.

**For Guardian Kit**: if the stages are a fixed pipeline, do not use subagents for orchestration. Run one `query()` per stage from Python (8.11). Subagents are for when the model should decide whether to delegate.

### 8.7 Hooks (`PreToolUse` deny)

**[verbatim]** (hooks page):

```python
import asyncio
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeSDKClient,
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
)


# Define a hook callback that receives tool call details
async def protect_env_files(input_data, tool_use_id, context):
    # Extract the file path from the tool's input arguments
    file_path = input_data["tool_input"].get("file_path", "")
    file_name = file_path.split("/")[-1]

    # Block the operation if targeting a .env file
    if file_name == ".env":
        return {
            "hookSpecificOutput": {
                "hookEventName": input_data["hook_event_name"],
                "permissionDecision": "deny",
                "permissionDecisionReason": "Cannot modify .env files",
            }
        }

    # Return empty object to allow the operation
    return {}


async def main():
    options = ClaudeAgentOptions(
        hooks={
            # Register the hook for PreToolUse events
            # The matcher filters to only Write and Edit tool calls
            "PreToolUse": [HookMatcher(matcher="Write|Edit", hooks=[protect_env_files])]
        }
    )

    async with ClaudeSDKClient(options=options) as client:
        await client.query("Create a .env file with the standard local development database configuration")
        async for message in client.receive_response():
            # Filter for assistant and result messages
            if isinstance(message, (AssistantMessage, ResultMessage)):
                print(message)


asyncio.run(main())
```

Facts:

- Python SDK callback events: `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `Stop`, `SubagentStart`, `SubagentStop`, `PreCompact`, `PermissionRequest`, `Notification`. **`SessionStart` / `SessionEnd` are not available as Python callbacks** (only as shell hooks from settings files).
- `HookMatcher(matcher=..., hooks=[...], timeout=<seconds>)`. Matchers match tool names (`"Bash"`, `"Write|Edit"`, `"^mcp__"`); filter on arguments inside the callback.
- Return `{}` to allow unchanged. Python spellings of reserved-word fields: `continue_`, `async_`.
- `updatedInput` goes inside `hookSpecificOutput`; pair it with `permissionDecision: "allow"` or `"ask"`.
- `systemMessage` is shown to the user, not the model; use `additionalContext` to tell the model.
- Hook callback timeout defaults to 600s. A timed-out `PreToolUse` callback means the tool is **not** run and the turn continues.
- Hooks fire for **every** tool call, before every other permission step, and a hook deny holds even in `bypassPermissions`. This is the reliable place for policy.
- Hooks may not fire when the agent hits `max_turns`.

### 8.8 `can_use_tool` for a human approval gate

Types **[verbatim]**:

```python
CanUseTool = Callable[
    [str, dict[str, Any], ToolPermissionContext], Awaitable[PermissionResult]
]

@dataclass
class PermissionResultAllow:
    behavior: Literal["allow"] = "allow"
    updated_input: dict[str, Any] | None = None
    updated_permissions: list[PermissionUpdate] | None = None

@dataclass
class PermissionResultDeny:
    behavior: Literal["deny"] = "deny"
    message: str = ""
    interrupt: bool = False
```

`ToolPermissionContext` carries `tool_use_id`, `agent_id`, `title` (e.g. `Claude wants to read foo.txt`), `display_name`, `description`, `blocked_path`, `decision_reason`, `suggestions`.

Example **[verbatim]** (user-input page):

```python
import asyncio

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query
from claude_agent_sdk.types import (
    HookMatcher,
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
)


async def can_use_tool(
    tool_name: str, input_data: dict, context: ToolPermissionContext
) -> PermissionResultAllow | PermissionResultDeny:
    # Display the tool request
    print(f"\nTool: {tool_name}")
    if tool_name == "Bash":
        print(f"Command: {input_data.get('command')}")
        if input_data.get("description"):
            print(f"Description: {input_data.get('description')}")
    else:
        print(f"Input: {input_data}")

    # Get user approval
    response = input("Allow this action? (y/n): ")

    # Return allow or deny based on user's response
    if response.lower() == "y":
        # Allow: tool executes with the original (or modified) input
        return PermissionResultAllow(updated_input=input_data)
    else:
        # Deny: tool doesn't execute, Claude sees the message
        return PermissionResultDeny(message="User denied this action")


# Required workaround: dummy hook keeps the stream open for can_use_tool
async def dummy_hook(input_data, tool_use_id, context):
    return {"continue_": True}


async def prompt_stream():
    yield {
        "type": "user",
        "message": {
            "role": "user",
            "content": "Create a test file in /tmp and then delete it",
        },
    }


async def main():
    async for message in query(
        prompt=prompt_stream(),
        options=ClaudeAgentOptions(
            can_use_tool=can_use_tool,
            hooks={"PreToolUse": [HookMatcher(matcher=None, hooks=[dummy_hook])]},
        ),
    ):
        if isinstance(message, ResultMessage) and message.subtype == "success":
            print(message.result)


asyncio.run(main())
```

Three Python-specific requirements visible in that example:

1. the prompt is an **async generator** (streaming input), not a string;
2. a **dummy `PreToolUse` hook** is registered ("Required workaround: dummy hook keeps the stream open for can_use_tool");
3. always return `PermissionResultAllow(updated_input=input_data)` (before v2.1.207 an allow without it was rejected).

**When it fires**: only when the permission flow falls through to a prompt. It **never** fires for a tool listed bare in `allowed_tools`, matched by a settings allow rule, or approved by `acceptEdits` / `bypassPermissions`, and never in `dontAsk`. So for the tool you want gated: do **not** put it in `allowed_tools`, and use `permission_mode="default"`.

The callback "can stay pending indefinitely"; the run is paused until it returns.

Approval gate for a web UI **[composed]**. A `PreToolUse` hook is used instead of `can_use_tool` because it fires on every call regardless of allow rules and works with a plain string prompt:

```python
import asyncio
from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

pending: dict[str, asyncio.Future] = {}   # tool_use_id -> Future[bool], resolved by the UI

async def approval_gate(input_data, tool_use_id, context):
    fut = asyncio.get_running_loop().create_future()
    pending[tool_use_id] = fut
    await ui_publish({"type": "approval_needed", "id": tool_use_id,
                      "tool": input_data["tool_name"], "input": input_data["tool_input"]})
    try:
        approved = await asyncio.wait_for(fut, timeout=300)
    except asyncio.TimeoutError:
        approved = False
    finally:
        pending.pop(tool_use_id, None)

    if approved:
        return {}  # fall through to the normal permission flow (tool is in allowed_tools)
    return {"hookSpecificOutput": {
        "hookEventName": input_data["hook_event_name"],
        "permissionDecision": "deny",
        "permissionDecisionReason": "A human reviewer rejected this action. Do not retry it.",
    }}

options = ClaudeAgentOptions(
    mcp_servers={"actions": actions_server},
    allowed_tools=["mcp__actions__*"],
    hooks={"PreToolUse": [HookMatcher(matcher="mcp__actions__apply_fix",
                                      hooks=[approval_gate], timeout=330)]},
)
# The UI endpoint calls: pending[tool_use_id].set_result(True / False)
```

Set the `HookMatcher` `timeout` above your own wait; if the hook itself times out the tool is not run.

### 8.9 `permission_mode`, `setting_sources`, limits

`PermissionMode` **[verbatim]**:

```python
PermissionMode = Literal[
    "default",  # Standard permission behavior
    "acceptEdits",  # Auto-accept file edits
    "plan",  # Planning mode - explore without editing
    "dontAsk",  # Deny anything not pre-approved instead of prompting
    "bypassPermissions",  # Bypass permission checks; explicit ask rules still prompt (use with caution)
    "auto",  # A model classifier reviews actions such as shell commands and network requests
]
```

| Mode | Use for the runtime |
| :-- | :-- |
| `default` | Unapproved calls go to `can_use_tool`; with no callback they are denied |
| `dontAsk` | **Best for headless pipeline stages**: pre-approved tools run, everything else that would prompt is denied |
| `acceptEdits` | Auto-approves file edits and `mkdir/touch/rm/rmdir/mv/cp/sed` inside the working dir |
| `plan` | No file edits auto-approved |
| `bypassPermissions` | Everything runs; refuses to start as root/sudo outside a recognised sandbox. Subagents inherit it. Avoid in a demo |
| `auto` | Classifier decides |

`setting_sources` **[verbatim type]**: `SettingSource = Literal["user", "project", "local"]`

- **Default (omitted / `None`) loads user, project and local settings, the same as the CLI.** That means `~/.claude/settings.json`, the repo's `.claude/settings.json`, CLAUDE.md, skills, filesystem hooks and permission rules all apply to your runtime agents unless you opt out.
- `setting_sources=[]` disables all three (Python SDK 0.1.59 and earlier treated `[]` as unset - use a current version).
- `setting_sources=["project"]` loads only the repo's `.claude/` and CLAUDE.md.
- With `skills` set and `setting_sources` unset, only user and project load.
- Programmatic options override filesystem settings; managed policy overrides everything.

For reproducible demo agents use `setting_sources=[]` and pass everything in code.

Limits:

| Option | Meaning | Default | On hit |
| :-- | :-- | :-- | :-- |
| `max_turns` | Max tool-use round trips (counts tool-use turns only) | none | `ResultMessage.subtype == "error_max_turns"` |
| `max_budget_usd` | Stop when the client-side cost estimate reaches this; includes subagents | none | `"error_max_budget_usd"` |
| `task_budget={"total": 50000}` | API-side task budget in tokens | none | |

### 8.10 Results, cost, usage

`ResultMessage` **[verbatim]**:

```python
@dataclass
class ResultMessage:
    subtype: str
    duration_ms: int
    duration_api_ms: int
    is_error: bool
    num_turns: int
    session_id: str
    stop_reason: str | None = None
    total_cost_usd: float | None = None
    usage: dict[str, Any] | None = None
    result: str | None = None
    structured_output: Any = None
    model_usage: dict[str, ModelUsage] | None = None
    permission_denials: list[Any] | None = None
    deferred_tool_use: DeferredToolUse | None = None
    errors: list[str] | None = None
    api_error_status: int | None = None
    uuid: str | None = None
    terminal_reason: str | None = None
    origin: MessageOrigin | None = None
```

- `subtype`: `"success"`, `"error_during_execution"`, `"error_max_turns"`, `"error_max_budget_usd"`, `"error_max_structured_output_retries"`.
- `result` is only populated on `success`.
- `is_error` can be `True` **on `subtype="success"`** when the final model request failed; check `api_error_status`.
- `stop_reason`: `end_turn`, `max_tokens`, `refusal`, ...
- `usage` keys (snake_case): `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`. Covers the **main loop only**, not subagents.
- `model_usage` maps model name to a dict with **camelCase** keys: `inputTokens`, `outputTokens`, `cacheReadInputTokens`, `cacheCreationInputTokens`, `webSearchRequests`, `costUSD`, `contextWindow`, `maxOutputTokens` (+ optional `thinkingTokens`, `canonicalModel`, `provider`). Includes subagents. Prefer it for accounting.
- `total_cost_usd` and `costUSD` are **client-side estimates** from a bundled price table. "Do not bill end users or trigger financial decisions from these fields."
- `total_cost_usd`, `usage`, `model_usage` are `Optional` in Python - guard for `None`.
- Each `query()` reports only its own cost; sum across calls yourself. Error results still carry cost.
- Per-step usage is on `AssistantMessage.usage` / `AssistantMessage.message_id`; parallel tool calls share one `message_id` (dedupe), and per-step `output_tokens` is a placeholder.

Cost accumulation **[verbatim]**:

```python
from claude_agent_sdk import query, ResultMessage
import asyncio


async def main():
    # Track cumulative cost across multiple query() calls
    total_spend = 0.0

    prompts = [
        "Read the files in src/ and summarize the architecture",
        "List all exported functions in src/auth.ts",
    ]

    for prompt in prompts:
        try:
            async for message in query(prompt=prompt):
                if isinstance(message, ResultMessage):
                    cost = message.total_cost_usd or 0
                    total_spend += cost
                    print(f"This call: ${cost}")
        except Exception as error:
            # A single-shot query() raises after yielding an error result. If
            # the failure was an error result, this call's cost was already
            # counted; connection or process failures yield no result message.
            # Continue with the next prompt.
            print(f"Call failed: {error}")

    print(f"Total spend: ${total_spend:.4f}")


asyncio.run(main())
```

Other message types: `SystemMessage(subtype, data)` (first one is `init`; also `compact_boundary`), `AssistantMessage(content, model, parent_tool_use_id, error, usage, message_id, stop_reason, session_id, uuid)`, `UserMessage` (tool results), `StreamEvent`, `RateLimitEvent`, `ConversationResetMessage`. `AssistantMessage.error` is one of `authentication_failed`, `billing_error`, `rate_limit`, `invalid_request`, `server_error`, `unknown` (other strings possible).

### 8.11 Streaming partial messages to a UI

`StreamEvent` **[verbatim]** (import from `claude_agent_sdk.types`):

```python
@dataclass
class StreamEvent:
    uuid: str  # Unique identifier for this event
    session_id: str  # Session identifier
    event: dict[str, Any]  # The raw Claude API stream event
    parent_tool_use_id: str | None  # Always None
```

UI example **[verbatim]**:

```python
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage
from claude_agent_sdk.types import StreamEvent
import asyncio
import sys


async def streaming_ui():
    options = ClaudeAgentOptions(
        include_partial_messages=True,
        allowed_tools=["Read", "Bash", "Grep"],
    )

    # Track whether we're currently in a tool call
    in_tool = False

    async for message in query(
        prompt="Find all TODO comments in the codebase", options=options
    ):
        if isinstance(message, StreamEvent):
            event = message.event
            event_type = event.get("type")

            if event_type == "content_block_start":
                content_block = event.get("content_block", {})
                if content_block.get("type") == "tool_use":
                    # Tool call is starting - show status indicator
                    tool_name = content_block.get("name")
                    print(f"\n[Using {tool_name}...]", end="", flush=True)
                    in_tool = True

            elif event_type == "content_block_delta":
                delta = event.get("delta", {})
                # Only stream text when not executing a tool
                if delta.get("type") == "text_delta" and not in_tool:
                    sys.stdout.write(delta.get("text", ""))
                    sys.stdout.flush()

            elif event_type == "content_block_stop":
                if in_tool:
                    # Tool call finished
                    print(" done", flush=True)
                    in_tool = False

        elif isinstance(message, ResultMessage):
            # Agent finished all work
            print(f"\n\n--- Complete ---")


asyncio.run(streaming_ui())
```

- Event types: `message_start`, `content_block_start`, `content_block_delta` (`text_delta`, `input_json_delta` with `partial_json`), `content_block_stop`, `message_delta`, `message_stop`.
- Deltas are raw; accumulate text yourself.
- **Stream events are emitted for the main session only**; token deltas from subagents are not forwarded. For subagent attribution use complete messages (`parent_tool_use_id`).
- Structured output does not stream.
- Without `include_partial_messages` you still get whole `AssistantMessage`s per turn, which is enough for a "stage N: calling tool X" progress UI and simpler to render.

### 8.12 Several independent agents concurrently **[composed]**

Each `query()` is an independent session backed by its own CLI subprocess, so they can run side by side under `asyncio`. Nothing in the docs read here states a concurrency limit for separate `query()` calls; the binding limits are API rate limits and process count, so cap with a semaphore.

```python
import asyncio
import json
from dataclasses import dataclass
from typing import Any
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

@dataclass
class StageResult:
    name: str
    ok: bool
    data: Any = None
    cost_usd: float = 0.0
    error: str | None = None

SEM = asyncio.Semaphore(4)

async def run_stage(name: str, prompt: str, schema: dict, options_kwargs: dict) -> StageResult:
    out = StageResult(name=name, ok=False)
    options = ClaudeAgentOptions(
        output_format={"type": "json_schema", "schema": schema},
        setting_sources=[],
        permission_mode="dontAsk",
        max_turns=10,
        max_budget_usd=0.75,
        **options_kwargs,
    )
    async with SEM:
        try:
            # Do not `break` out of this loop: the docs warn it causes asyncio cleanup issues.
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, ResultMessage):
                    out.cost_usd = message.total_cost_usd or 0.0
                    if (message.subtype == "success" and not message.is_error
                            and message.structured_output):
                        out.ok, out.data = True, message.structured_output
                    else:
                        out.error = message.subtype if message.subtype != "success" else "no_structured_output"
        except Exception as exc:
            # A single-shot query() raises AFTER yielding an error result, so `out`
            # may already hold the subtype and cost. Connection/process failures land here only.
            out.error = out.error or f"{type(exc).__name__}: {exc}"
    return out

async def run_all(stages: list[tuple[str, str, dict, dict]]) -> list[StageResult]:
    return await asyncio.gather(*(run_stage(*s) for s in stages))
```

Sequential-with-handoff pipelines are the same function called in a loop, passing `json.dumps(previous.data)` into the next prompt. Passing JSON between stages (instead of resuming one long session) keeps every stage's context small and makes each stage cacheable.

### 8.13 Models, effort, thinking

`model: str | None` - "Claude model alias or full model name". Unset means Claude Code's default for the account. Pin it for a demo.

**Aliases** (model-config page):

| Alias | Resolves to (Anthropic API) |
| :-- | :-- |
| `fable` | Fable 5.1 (unless `ANTHROPIC_DEFAULT_FABLE_MODEL` is set) |
| `best` | what `fable` resolves to where available, otherwise `opus` |
| `opus` | Opus 5.5 |
| `sonnet` | Sonnet 5.5 |
| `haiku` | Haiku 5.5 |
| `opusplan` | `opus` in plan mode, then `sonnet` |
| `sonnet[1m]`, `opus[1m]` | 1M-context variants (no effect when the alias already resolves to a native-1M model) |
| `default` | clears the override (Opus 5.5 for most account types) |

On Bedrock / Vertex the aliases resolve differently (e.g. `sonnet` to Sonnet 4.5, `haiku` to Haiku 4.5); on Claude Platform on AWS `sonnet` is Sonnet 4.6.

**Full IDs seen in the docs read**: `claude-fable-5-1`, `claude-fable-5`, `claude-opus-5-5`, `claude-opus-5`, `claude-sonnet-5`, `claude-sonnet-4-6`, `claude-sonnet-4-5`, `claude-sonnet-4-5-20250929`, `claude-opus-4-6`, `claude-haiku-5-5`, `claude-haiku-4-5`. Sonnet 5.5 is named on the page but its ID string (`claude-sonnet-5-5` by pattern) was **not** printed - **[unverified]**. Model IDs were extracted through a summarising fetch, so confirm the exact strings at `https://platform.claude.com/docs/en/about-claude/models/overview` before hard-coding. Aliases are the safer choice in code; a full ID is the safer choice for a reproducible demo.

`AgentDefinition.model` accepts `'fable'`, `'opus'`, `'sonnet'`, `'haiku'`, `'inherit'`, or a full ID.

`fallback_model`: used if the primary model fails; accepts a comma-separated list (chain capped at three per the model-config page).

`EffortLevel` **[verbatim]**:

```python
EffortLevel = Literal[
    "low",  # Minimal thinking, fastest responses
    "medium",  # Moderate thinking
    "high",  # Deep reasoning
    "xhigh",  # Extended reasoning; falls back to "high" on models that don't support it
    "max",  # Maximum effort
]
```

Unset `effort` defers to the model default (`medium` on Opus/Sonnet/Haiku 5.5, `high` on most others, `xhigh` on Opus 4.7). Supported levels: all five on Fable 5.x, Opus/Sonnet/Haiku 5.5, Opus 5, Sonnet 5, Opus 4.8, Opus 4.7; no `xhigh` on Opus 4.6 / Sonnet 4.6. Use `effort="low"` for lookup-style stages.

`ThinkingConfig` **[verbatim]**:

```python
ThinkingDisplay = Literal["summarized", "omitted"]


class ThinkingConfigAdaptive(TypedDict):
    type: Literal["adaptive"]
    display: NotRequired[ThinkingDisplay]


class ThinkingConfigEnabled(TypedDict):
    type: Literal["enabled"]
    budget_tokens: int
    display: NotRequired[ThinkingDisplay]


class ThinkingConfigDisabled(TypedDict):
    type: Literal["disabled"]


ThinkingConfig = ThinkingConfigAdaptive | ThinkingConfigEnabled | ThinkingConfigDisabled
```

- Pass as a dict: `thinking={"type": "adaptive", "display": "summarized"}`.
- On Opus 4.7 and later the API default `display` is `"omitted"`; set `"summarized"` if the UI should show thinking text.
- Newer models (Fable, Sonnet 5+, Haiku 5.5, Opus 4.7+) always use adaptive reasoning; a fixed `budget_tokens` does not apply, and thinking cannot be turned off on the 5.5 models and Fable - effort is the control there.
- `effort` and `thinking` are independent settings.
- `max_thinking_tokens` is deprecated.

## 9. Pitfalls, error handling, robustness

### 9.1 Things the docs say that people get wrong

1. **`allowed_tools` is not an allowlist.** It pre-approves; unlisted tools stay available. Restrict with `tools=[...]` (availability) and/or `disallowed_tools`, and `permission_mode="dontAsk"`.
2. **`allowed_tools` + `bypassPermissions` approves everything.**
3. **`can_use_tool` only fires when the flow reaches a prompt.** Never for auto-approved tools, never in `dontAsk`. Use a `PreToolUse` hook for checks that must always run.
4. **Python `can_use_tool` needs streaming input plus a dummy `PreToolUse` hook.**
5. **Subagents run in the background by default** (`status: "async_launched"`).
6. **`AgentDefinition` fields are camelCase** (`disallowedTools`, `maxTurns`, `permissionMode`, `mcpServers`, `initialPrompt`); a snake_case keyword raises `TypeError`. `ClaudeAgentOptions` is snake_case. `model_usage` values are camelCase dicts; `usage` is snake_case.
7. **The SDK loads filesystem settings by default** (user + project + local), including CLAUDE.md, skills, hooks and permission rules. Pass `setting_sources=[]` for isolation.
8. **No separate Claude Code/Node install is needed** in most cases; the wheel bundles the binary.
9. **`.env` is not auto-loaded.**
10. **`subtype == "success"` is not success.** Also check `is_error` and, for structured output, that `structured_output` is not `None`.
11. **A single-shot `query()` raises after yielding an error result** (e.g. max turns, budget). The `ResultMessage` arrives first, then the exception. Wrap every loop in `try/except`.
12. **Do not `break` out of `async for ... in query()`** ("can cause asyncio cleanup issues"). Trailing events can also arrive after the `ResultMessage`; iterate to completion.
13. **`TypedDict` configs are plain dicts** (`config["budget_tokens"]`, not attribute access); `@dataclass` types use attributes.
14. **Custom-command files and skills are the same thing now**; skill wins on a name clash.
15. **Bash deny rules are not a security boundary** (`git -C . push` slips past `Bash(git push *)`).
16. **`:*` is still valid** as a trailing wildcard, equivalent to ` *`.
17. **Subagents can nest** (three layers by default) - older guidance said they could not.
18. **Cost fields are estimates**, and `usage` excludes subagents.
19. **`Edit(/secrets/**)` is not an absolute path**; absolute is `Edit(//secrets/**)`.
20. **Tool name is `Agent` in tool_use blocks but `Task` in the init tools list.**
21. **The server key in `mcp_servers`, not the `name=` argument, forms `mcp__<server>__<tool>`.**
22. **Unknown frontmatter fields in skills/agents are ignored silently** - a typo fails with no error.

### 9.2 Error handling

Exception classes confirmed in the troubleshooting page:

| Exception | When | Useful attributes |
| :-- | :-- | :-- |
| `CLINotFoundError` | No `claude` binary found (`Claude Code not found at: ...`) | |
| `CLIConnectionError` | Binary found but failed to start; `Not connected. Call connect() first.`; Windows `.cmd` shim refused | |
| `ProcessError` | CLI exited non-zero without an error result | `exit_code`; `stderr` is fixed text, not real stderr |
| `ResultError` (subclass of `ProcessError`, SDK 0.2.140+) | CLI reported an error result then exited: `Claude Code returned an error result: ...` | `data` (the full error result) |

`ClaudeSDKError` (base) and `CLIJSONDecodeError` are commonly cited but were **not** on the pages read - **[unverified]**; `except Exception` is what every docs example uses.

To see real stderr, pass `ClaudeAgentOptions(stderr=lambda line: log.debug(line))`.

Order `except ResultError` before `except ProcessError` if you treat them differently.

API-level failures show up three ways: `AssistantMessage.error` (`rate_limit`, `server_error`, ...), `ResultMessage.is_error` / `api_error_status`, and `subtype == "error_during_execution"`. The CLI retries retryable API errors itself.

In tools: catch inside the handler and return `"is_error": True` with a message Claude can act on.

### 9.3 Timeouts

- No per-query wall-clock timeout option was found in the options read. Bound runs with `max_turns` and `max_budget_usd`.
- For a hard wall-clock limit use `ClaudeSDKClient` and call `await client.interrupt()` from a watchdog task, then drain `receive_response()`. Wrapping `query()` in `asyncio.wait_for` cancels the generator mid-iteration, which is the situation the "avoid break" note warns about - **[unverified]** whether cleanup is clean; test it before relying on it.
- `load_timeout_ms=60_000` on the options (startup). MCP: `MCP_TIMEOUT`, `MCP_TOOL_TIMEOUT` via `env`.
- Hook callbacks: `HookMatcher(timeout=<seconds>)`, default 600.
- Put your own `httpx` timeouts inside every custom tool.

### 9.4 Making the demo robust **[composed advice]**

1. **Cache every stage result.** Key = SHA-256 of (stage name, model, system prompt, prompt, schema, tool-set version). Store the validated `structured_output` JSON on disk. Demo mode reads the cache first; a `--live` flag bypasses it.
2. **Deterministic fallback per stage.** Each stage has a pure-Python function (rules/heuristics or a recorded fixture) that returns the same Pydantic model. `run_stage` returns the fallback, flagged `source="fallback"`, when `ok` is false. The UI shows the flag honestly.
3. **Validate at the boundary**: `Model.model_validate(structured_output)`; on `ValidationError` use the fallback.
4. **Record and replay the stream.** Persist the sequence of UI events for a good run so the live-looking demo can be replayed with no network.
5. **Pre-flight check** at app start: one tiny `query()` with `max_turns=1`; if it raises `CLINotFoundError` / auth error, switch the whole app to replay mode and show a banner.
6. **Pin the model and SDK version** (`uv lock`); set `setting_sources=[]` so a teammate's `~/.claude` cannot change behaviour.
7. **Budget every stage** (`max_turns`, `max_budget_usd`) and cap concurrency with a semaphore to stay under rate limits.
8. **Keep tools idempotent and side-effect-free in demo mode**; gate real side effects behind the approval hook (8.8).
9. **Log** `session_id`, `subtype`, `num_turns`, `duration_ms`, `total_cost_usd`, `model_usage` per stage; `session_id` lets you `resume` to inspect a failure.
10. **Docker**: install the SDK in the image build; do not run as root with `bypassPermissions` (it refuses to start).

## 10. Alternative: plain Messages API tool use

**[from general knowledge; the Messages API docs were not read in this session]** - the Agent SDK structured-outputs page itself points to "API Structured Outputs" for "single-turn requests without tool use".

| | Agent SDK | Messages API (`anthropic` package) |
| :-- | :-- | :-- |
| Runtime | Spawns a Claude Code subprocess per session | One HTTPS request per turn, in-process |
| Loop | Built in: tool execution, retries, compaction, permissions, hooks, subagents | You write the `while stop_reason == "tool_use"` loop |
| Built-in tools | Read/Edit/Bash/Grep/WebSearch/... | None client-side; you implement each tool |
| Startup latency / footprint | Higher (process spawn, bundled binary) | Minimal |
| Determinism / control | Extra system prompt, tool search, settings loading unless disabled | Exactly the request you send |
| Structured output | `output_format`, validated with retries, after multi-turn tool use | Native structured outputs / forced tool choice, single request |
| Cost visibility | Client-side estimate | Exact token `usage` per response |

Rule of thumb for Guardian Kit:

- **Use the Messages API** for a stage that is "one prompt in, one JSON object out" or a classification/extraction with at most one or two of your own tools. It is faster, cheaper, easier to test, easier to cache and has no subprocess to fail on stage.
- **Use the Agent SDK** for a stage that genuinely needs an open-ended loop: exploring a repository or file tree, running commands, many tool calls with unknown depth, human approval gates via hooks, or delegation to subagents.
- Mixing is fine: both read `ANTHROPIC_API_KEY`, and a stage is just an async function returning a Pydantic model.

---

## Sources

Read on 2026-11-23 (raw markdown via the `.md` suffix). Pages over 100k characters were read only up to that point unless noted.

Index:

- https://code.claude.com/docs/llms.txt

Claude Code:

- https://code.claude.com/docs/en/memory.md
- https://code.claude.com/docs/en/sub-agents.md (first 100k chars)
- https://code.claude.com/docs/en/skills.md (first 100k chars)
- https://code.claude.com/docs/en/settings.md
- https://code.claude.com/docs/en/permissions.md
- https://code.claude.com/docs/en/hooks.md (first 100k chars)
- https://code.claude.com/docs/en/mcp.md (first 100k chars)
- https://code.claude.com/docs/en/headless.md
- https://code.claude.com/docs/en/checkpointing.md
- https://code.claude.com/docs/en/best-practices.md
- https://code.claude.com/docs/en/model-config.md (first 100k chars; extracted by summary, not raw)

Agent SDK:

- https://code.claude.com/docs/en/agent-sdk/quickstart.md
- https://code.claude.com/docs/en/agent-sdk/python.md (chars 0-100k and 100k-137k; the tail after `StreamEvent`, including the error-class reference, was cut off)
- https://code.claude.com/docs/en/agent-sdk/agent-loop.md
- https://code.claude.com/docs/en/agent-sdk/custom-tools.md
- https://code.claude.com/docs/en/agent-sdk/structured-outputs.md
- https://code.claude.com/docs/en/agent-sdk/subagents.md
- https://code.claude.com/docs/en/agent-sdk/permissions.md
- https://code.claude.com/docs/en/agent-sdk/user-input.md
- https://code.claude.com/docs/en/agent-sdk/hooks.md
- https://code.claude.com/docs/en/agent-sdk/streaming-output.md
- https://code.claude.com/docs/en/agent-sdk/cost-tracking.md
- https://code.claude.com/docs/en/agent-sdk/troubleshooting.md

Not read (referenced only; verify before relying on the items marked [unverified]):

- https://code.claude.com/docs/en/worktrees.md (`claude --worktree`)
- https://code.claude.com/docs/en/settings-reference.md (`env` key format, `strict_mcp_config` equivalent)
- https://code.claude.com/docs/en/commands.md, https://code.claude.com/docs/en/permission-modes.md
- https://code.claude.com/docs/en/agent-sdk/streaming-vs-single-mode.md, sessions.md, mcp.md, hosting.md
- https://platform.claude.com/docs/en/about-claude/models/overview (exact model IDs)
- https://platform.claude.com/docs/en/build-with-claude/structured-outputs (Messages API structured outputs)
- Playwright MCP and Context7 READMEs (install lines in 6.2)
