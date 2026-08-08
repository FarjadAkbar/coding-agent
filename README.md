# Terminal Coding Agent (terminal.py)

## Overview
`terminal.py` is a secure, interactive coding agent framework designed for automating terminal/codebase tasks safely using a combination of LLM-driven repl, Docker sandboxing, file diffing, and git checkpoints.

## Features
- **Sandboxed Shell Execution**: All shell commands are executed inside a temporary, resource-limited Docker container (no network, only project files visible). Protects host from harmful commands.
- **Safe Command Classification**: Uses regex-based gates to classify commands as safe to auto-run, requiring confirmation, or completely blocked (e.g., `rm -rf`, `sudo`, `curl | sh`).
- **Integrated Source Editing**: Read, write, and modify project files with verification (e.g., Python files are compiled, JSON files are validated post-write).
- **Git-integrated Checkpoints**: Every file change prompts a git commit, enabling rollbacks via the `/undo` command.
- **Session Usage & Cost Tracking**: Tracks input/output tokens and API calls for LLM usage, estimating session costs.
- **Agent/LLM REPL Loop**: Supports conversational prompts and complex task handling via iterative agent turns with tool function calls. 
- **Configurable**: Behavior, model, Docker image, and tool lists can be customized via `.agent.json` (auto-created at first startup).

## Security By Design
- **Dockerized Shell**: Lockdown with no outbound network, non-root, resource caps, and project-root-only filesystem.
- **Regex Command Filtering**: Prevents dangerous system actions from executing.
- **Path and Diff Checks**: Prevents directory traversal; user approves file diffs interactively before write.
- **Git Backups**: Enables undo on every write, limiting the impact of mistakes or malicious commands.

## Quickstart
```
python terminal.py         # Start agent in REPL mode
python terminal.py --init-config  # Generate default config file
```

- `/undo`: Revert the last change (uses git)
- `/usage`: Show current session's OpenAI model usage and estimated cost

## Typical Workflow
1. Start the agent in your project directory
2. Type coding or shell tasks�you can ask for file edits, new code, run build commands, etc.
3. Changes will be previewed (with file diff), confirmed by you, and committed to git.
4. Unsafe commands must be confirmed; blocked commands (e.g., `rm -rf`) are refused by design.

## Example Agent-Driven Session
```
you> add a function to hello.py to print prime numbers
(agent proposes file change, shows diff, you approve)
you> run python hello.py
(agent safely runs command in isolated container)
you> /undo
(reverts the last file/code change via git)
```

## Requirements
- Python 3.8+
- Docker (must be installed and available on PATH)
- Git (for checkpoints/undo)

## License
Open-source. Use at your own risk. Review and test before using on sensitive projects.

## Why Use This?
- Develop and automate code with robust safety rails
- Experiment safely with agent-driven code changes
- Clean rollback and tight auditability via git
- Bulletproof against shell-injection and file-destructive mistakes

---
This project is for anyone wanting to combine LLM/dev agent tools with real codebase automation�while keeping their system safe.
