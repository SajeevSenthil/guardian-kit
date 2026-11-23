#!/usr/bin/env python3
"""PreToolUse hook for Bash: blocks actions the hackathon rules put out of scope.

Reads the hook JSON on stdin. Exit 2 blocks the call and shows stderr to Claude.
Permission deny-rules miss spellings like `git -C . push`, so this inspects the command text.
To avoid blocking harmless text (a commit message that mentions "git push", a grep for
"npm publish"), quoted strings are removed first and a rule only matches when the program
name is at the start of a command (line start or after ; & | ( ).

It is a guard rail, not a security boundary: the real protections are that the demo target
has no git remote and no credentials are present.
"""

import json
import re
import sys

CMD = r"(?:^|[;&|(]\s*|\b(?:sudo|env|time|xargs)\s+)"  # command position
OPTS = r"(?:\s+-{1,2}\S+(?:[ =]\S+)?)*"  # leading global options such as -C dir, -c k=v

RULES = [
    (CMD + r"git" + OPTS + r"\s+push\b", "git push is a human-only step."),
    (CMD + r"(?:npm|pnpm|yarn)\s+publish\b", "publishing packages is out of scope."),
    (CMD + r"docker\s+(?:image\s+)?push\b", "pushing images is out of scope."),
    (CMD + r"(?:twine\s+upload|uv\s+publish)\b", "publishing packages is out of scope."),
    (
        CMD + r"gh\s+(?:pr\s+(?:create|merge)|release\s+create|repo\s+create)\b",
        "opening or merging pull requests and creating releases are human-only steps.",
    ),
    (CMD + r"(?:nmap|masscan|sqlmap|nikto)\b", "scanning or attacking systems is out of scope."),
]


def strip_quoted(text: str) -> str:
    """Remove '...' and "..." spans so words inside messages and patterns do not match."""
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", " Q ", text)


def main() -> int:
    try:
        cmd = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    except Exception:
        return 0
    bare = strip_quoted(cmd)
    for pattern, why in RULES:
        if re.search(pattern, bare, flags=re.MULTILINE):
            print(
                f"Blocked by project hook: {why} If it is really needed, ask the human to run it.",
                file=sys.stderr,
            )
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
