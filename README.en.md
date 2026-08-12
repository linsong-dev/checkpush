<h1 align="center">CheckPush</h1>

<p align="center">
  <b>Audit-first publishing for Codex skills: review before you push, gate before you release</b><br>
  Encoding pre-check · sensitive-info sanitization · auto tests · gated push · remote verification
</p>

<p align="center">
  [![中文](https://img.shields.io/badge/中文-README-red)](README.md) | [![EN](https://img.shields.io/badge/EN-README-blue)](README.en.md) |
  <a href="https://github.com/linsong-dev/checkpush/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
  </a>
  <img src="https://img.shields.io/badge/version-2.3.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-orange" alt="Python">
</p>

---

## What CheckPush Is in 30 Seconds

Before publishing a Codex skill repository to GitHub, CheckPush runs an **automatic gate**: encoding (BOM / mojibake / replacement chars), syntax (JSON / YAML / TOML), sensitive info (tokens / personal paths), and git hygiene (CRLF/LF mixing, history leaks). Problems are sent back; only clean pushes go out.

> Normal publishing: `git add && git commit && git push` (problems already live on the public internet)
>
> Audit-push: `pre-check` → `sanitize` → `verify` → `push` → `review` (audit first, push second)

## Features

- **Five-stage universal flow**: audit → sanitize → verify → push → review (remote sync verification)
- **Full encoding audit**: BOM / mojibake / replacement chars / encoding errors; garbled Chinese files are blocked before push
- **Syntax validation**: JSON / YAML / TOML checks + CRLF/LF line-ending mixing detection
- **Sensitive-info scanning**: tokens / credentials / personal paths (like `Drive:\Users\username`) including history-leak checks
- **Sanitizer**: `sanitize` preview → `--apply` auto-replaces personal paths with automatic backup
- **Auto verification**: `verify` runs pytest + self-check scripts, exit code 0/1
- **Gated push**: push auto-runs the audit gate + fork detection + change summary + direct fetch verification after push
- **One-click plugin sync**: `sync` copies SKILL.md / README / LICENSE / plugin.json / assets from a runtime main dir to the source repo and pushes
- **Last line of defense**: `scan-mindol` scans the memory DB (memory.db) for leftover tokens/credentials

## Requirements

- Python 3.10+ (standard library only; `websocket-client` optional for CDP browser login)
- git + a GitHub account (token in `.gh_token`, excluded by .gitignore, never uploaded)
- PowerShell 5.1+ (Windows)

## Install

```powershell
git clone https://github.com/linsong-dev/checkpush.git
cd checkpush
# Optional: enhanced browser login
pip install websocket-client
```

Write your GitHub token to `.gh_token` (one line, no newline).

## Quick Usage

```powershell
# 1. Pre-check (audit only, no push)
python scripts/checkpush.py pre-check --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill

# 2. Push (with automatic audit gate)
python scripts/checkpush.py push --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --message "update description"

# 3. One-click plugin sync (runtime main → source repo → git; optional --agents + --plugin to reinstall)
python scripts/checkpush.py sync --owner linsong-dev --repo my-skill --dir S:\xxx\my-skill --run E:\xxx\my-skill --message "sync plugin info"

# 4. Audit / sanitize preview / verify separately
python scripts/checkpush.py audit --dir S:\xxx\my-skill
python scripts/checkpush.py sanitize --dir S:\xxx\my-skill          # preview
python scripts/checkpush.py sanitize --dir S:\xxx\my-skill --apply  # apply
python scripts/checkpush.py verify --dir S:\xxx\my-skill

# 5. Memory DB sensitive scan
python scripts/checkpush.py scan-mindol
```

## Workflow (Five Stages)

```text
audit (encoding + syntax + sensitive info + git hygiene)
   ↓ send back if issues
sanitize (personal-path redaction, automatic backup)
   ↓
verify (pytest + self-check)
   ↓
push (gate + fork detection + change summary)
   ↓
review (remote sync verification 0/0)
```

## Project Structure

```text
checkpush/
├── scripts/checkpush.py   main program (11 actions)
├── .codex-plugin/         Codex plugin metadata
├── SKILL.md               plugin doc + full command reference
├── .gh_token              GitHub token (gitignored, never uploaded)
└── LICENSE                Apache 2.0
```

## Security Notes

- `.gh_token` is excluded by `.gitignore`, and `audit` scans commit history for token/credential leaks
- Personal paths (like `Drive:\Users\username`) are redacted to placeholders before release by default, keeping local semantics
- Only token/credential-class secrets are replaced; paths are kept to avoid breaking semantic search context

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/linsong-dev">linsong-dev</a></sub>
</p>