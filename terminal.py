import difflib
import json
import os
import re
import shutil
import subprocess
from openai import OpenAI

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)
ROOT = os.getcwd()
CONFIG_PATH = os.path.join(ROOT, '.agent.json')

DEFAULT_CONFIG = {
    "model": "gpt-4.1",
    "docker_image": "python:3.11-slim",
    "container_timeout": 30,
    "max_turns_per_task": 12,
    "safe_prefixes": ["ls", "cat", "grep", "find", "git status", "git diff",
                       "git log", "pwd", "echo", "wc", "head", "tail"],
    "dangerous_patterns": [
        r"\brm\s+-rf\b", r"\bsudo\b", r"\bmkfs\b", r":\(\)\{",
        r"\bcurl\b.*\|\s*sh", r"\bgit\s+push\b",
        r"\bgit\s+reset\s+--hard\b", r"\bchmod\s+777\b",
    ],
    "verifiers": {".py": "python", ".json": "json"},
    "pricing_per_million": {"input": 2.00, "output": 8.00},
}

def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG

    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        return {**DEFAULT_CONFIG, **config}  # merge with defaults

def init_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"Created default config at {CONFIG_PATH}")
    else:
        print(f"Config already exists at {CONFIG_PATH}")


CONFIG = load_config()
DOCKER_IMAGE = CONFIG["docker_image"]
CONTAINER_TIMEOUT = CONFIG["container_timeout"]
MAX_TURNS_PER_TASK = CONFIG["max_turns_per_task"]
SAFE_PREFIXES = CONFIG["safe_prefixes"]
DANGEROUS_PATTERNS = CONFIG["dangerous_patterns"]
VERIFIERS = CONFIG["verifiers"]


class SessionUsage:
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.api_calls = 0

    def add_usage(self, input_tokens: int, output_tokens: int):
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.api_calls += 1

    def total_cost(self) -> float:
        input_cost = (self.input_tokens / 1_000_000) * CONFIG["pricing_per_million"]["input"]
        output_cost = (self.output_tokens / 1_000_000) * CONFIG["pricing_per_million"]["output"]
        return input_cost + output_cost

    def summary(self) -> str:
        return (f"Session usage: {self.input_tokens} input tokens, "
                f"{self.output_tokens} output tokens, "
                f"total cost: ${self.total_cost():.6f}, "
                f"API calls: {self.api_calls}")
USAGE = SessionUsage()
# ---------------------------------------------------------------------
# docker availability check — fail loud and clear, not confusingly
# ---------------------------------------------------------------------

def docker_available() -> bool:
    return shutil.which("docker") is not None


def ensure_image_pulled():
    """Pull once at startup so the first command a user runs isn't
    silently slow while Docker fetches the image."""
    print(f"Checking for Docker image {DOCKER_IMAGE}...")
    subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                    capture_output=True)  # ignore result, pull covers it
    subprocess.run(["docker", "pull", DOCKER_IMAGE], capture_output=True)


# ---------------------------------------------------------------------
# security gate — classification unchanged, execution path changes
# ---------------------------------------------------------------------

def is_git_repo() -> bool:
    return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=ROOT, capture_output=True).returncode == 0

def checkpoint(message: str):
    if not is_git_repo():
        print("[checkpoint skipped] Not a git repository.")
        return
    subprocess.run(["git", "add", "."], cwd=ROOT)
    subprocess.run(["git", "commit", "-m", f"Checkpoint: {message}"], cwd=ROOT, capture_output=True)

def undo_last() -> str:
    if not is_git_repo():
        return "[undo skipped] Not a git repository."
    log = subprocess.run(["git", "log", "-1", "--pretty=%B"], cwd=ROOT, capture_output=True, text=True)
    ans = input("Are you sure you want to undo the last commit? This will discard changes. [y/N] ")
    if ans.strip().lower() != "y":
        return "[undo cancelled] User did not approve undo."
    
    last_commit_msg = log.stdout.strip()
    result = subprocess.run(["git", "reset", "--hard", "HEAD~1"], cwd=ROOT)
    if result.returncode != 0:
        return "[undo failed] Could not revert the last commit."
    
    return f"[undo] Reverted last commit: {last_commit_msg}"

def classify_command(cmd: str) -> str:
    if any(re.search(p, cmd) for p in DANGEROUS_PATTERNS):
        return "blocked"
    if any(cmd.strip().startswith(p) for p in SAFE_PREFIXES):
        return "auto"
    return "confirm"


def safe_path(path: str) -> str:
    full = os.path.abspath(os.path.join(ROOT, path))
    if not (full == ROOT or full.startswith(ROOT + os.sep)):
        raise PermissionError(f"Path escapes project root: {path}")
    return full


def run_in_container(command: str) -> subprocess.CompletedProcess:
    """
    --rm              throwaway container, nothing persists between runs
    -v ROOT:/workspace:rw   ONLY the project dir is visible, nothing else on disk
    -w /workspace     commands run relative to the project root inside too
    --network none    no outbound network — blocks exfiltration and
                       curl-pipe-to-shell style attacks even if regex missed them
    --memory / --cpus resource caps so a runaway process can't take the host down
    --user 1000:1000  non-root inside the container
    --cap-drop ALL    drop all Linux capabilities (no raw sockets, no ptrace, etc)
    """
    docker_cmd = [
        "docker", "run", "--rm",
        "-v", f"{ROOT}:/workspace:rw",
        "-w", "/workspace",
        "--network", "none",
        "--memory", "512m",
        "--cpus", "1",
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        DOCKER_IMAGE,
        "bash", "-c", command,
    ]
    return subprocess.run(docker_cmd, capture_output=True, text=True,
                           timeout=CONTAINER_TIMEOUT)


# ---------------------------------------------------------------------
# verification (unchanged)
# ---------------------------------------------------------------------

def verify_python(full: str):
    check = subprocess.run(["python3", "-m", "py_compile", full],
                            capture_output=True, text=True)
    return None if check.returncode == 0 else check.stderr.strip()


def verify_json(full: str):
    try:
        with open(full, "r") as f:
            json.load(f)
        return None
    except json.JSONDecodeError as e:
        return str(e)



def verify_file(full: str):
    ext = os.path.splitext(full)[1]
    verifier = VERIFIERS.get(ext)
    return verifier(full) if verifier else None


def _apply_write(full: str, path: str, content: str) -> str:
    old = ""
    if os.path.exists(full):
        with open(full, "r", errors="replace") as f:
            old = f.read()

    diff = "\n".join(difflib.unified_diff(
        old.splitlines(), content.splitlines(),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
    ))
    print(f"\n--- diff for {path} ---\n{diff or '(no change)'}\n")

    ans = input("Apply this change? [y/N] ")
    if ans.strip().lower() != "y":
        return "[DENIED] User rejected the change."

    checkpoint(f"before editing {path}")

    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    tmp = full + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.replace(tmp, full)

    error = verify_file(full)
    if error:
        return f"[WRITTEN but FAILED VERIFICATION] {path}\n{error}"
    return f"[WRITTEN and VERIFIED] {path} ({len(content)} bytes)"


# ---------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------

def plan(steps: str) -> str:
    print(f"\n🧠 plan:\n{steps}\n")
    return "[LOGGED] Plan noted. Proceed with the steps."


def run_command(command: str) -> str:
    verdict = classify_command(command)

    if verdict == "blocked":
        return f"[BLOCKED] Command matched a dangerous pattern, not run: {command}"

    if verdict == "confirm":
        ans = input(f"\n⚠️  Model wants to run (in container): `{command}`\nAllow? [y/N] ")
        if ans.strip().lower() != "y":
            return "[DENIED] User did not approve this command."

    try:
        result = run_in_container(command)
    except subprocess.TimeoutExpired:
        return f"[ERROR] Command timed out after {CONTAINER_TIMEOUT}s (container killed)"
    except FileNotFoundError:
        return "[ERROR] Docker is not installed or not on PATH."

    out = (result.stdout or "") + (result.stderr or "")
    if len(out) > 4000:
        out = out[:4000] + "\n...[truncated]..."
    return f"exit_code={result.returncode}\n{out}"


def read_file(path: str) -> str:
    try:
        full = safe_path(path)
    except PermissionError as e:
        return f"[BLOCKED] {e}"
    with open(full, "r", errors="replace") as f:
        return f.read()


def list_dir(path: str = ".") -> str:
    try:
        full = safe_path(path)
    except PermissionError as e:
        return f"[BLOCKED] {e}"
    return "\n".join(sorted(os.listdir(full)))


def write_file(path: str, content: str) -> str:
    try:
        full = safe_path(path)
    except PermissionError as e:
        return f"[BLOCKED] {e}"
    return _apply_write(full, path, content)


def str_replace(path: str, old_str: str, new_str: str) -> str:
    try:
        full = safe_path(path)
    except PermissionError as e:
        return f"[BLOCKED] {e}"
    if not os.path.exists(full):
        return f"[ERROR] File does not exist: {path} (use write_file to create it)"
    with open(full, "r", errors="replace") as f:
        current = f.read()
    count = current.count(old_str)
    if count == 0:
        return "[ERROR] old_str not found in file. Re-read the file and match it exactly."
    if count > 1:
        return (f"[ERROR] old_str matches {count} places in the file — it must match "
                 "exactly once. Include more surrounding context to make it unique.")
    new_content = current.replace(old_str, new_str, 1)
    return _apply_write(full, path, new_content)


TOOL_IMPL = {
    "plan": lambda a: plan(a["steps"]),
    "run_command": lambda a: run_command(a["command"]),
    "read_file": lambda a: read_file(a["path"]),
    "list_dir": lambda a: list_dir(a.get("path", ".")),
    "write_file": lambda a: write_file(a["path"], a["content"]),
    "str_replace": lambda a: str_replace(a["path"], a["old_str"], a["new_str"]),
}

tools = [
    {"type": "function", "name": "plan",
     "description": "State your plan before any mutating action.",
     "parameters": {"type": "object",
                     "properties": {"steps": {"type": "string"}},
                     "required": ["steps"]}},
    {"type": "function", "name": "run_command",
     "description": "Run a shell command inside an isolated container (no network, no host filesystem access outside the project) and return the output.",
     "parameters": {"type": "object",
                     "properties": {"command": {"type": "string"}},
                     "required": ["command"]}},
    {"type": "function", "name": "read_file",
     "description": "Read a file's contents by path, relative to the project root.",
     "parameters": {"type": "object",
                     "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
    {"type": "function", "name": "list_dir",
     "description": "List files in a directory, relative to the project root.",
     "parameters": {"type": "object",
                     "properties": {"path": {"type": "string"}},
                     "required": []}},
    {"type": "function", "name": "write_file",
     "description": "Create a NEW file, or fully overwrite an existing one.",
     "parameters": {"type": "object",
                     "properties": {"path": {"type": "string"},
                                     "content": {"type": "string"}},
                     "required": ["path", "content"]}},
    {"type": "function", "name": "str_replace",
     "description": "Replace one exact, unique occurrence of old_str with new_str in an existing file.",
     "parameters": {"type": "object",
                     "properties": {"path": {"type": "string"},
                                     "old_str": {"type": "string"},
                                     "new_str": {"type": "string"}},
                     "required": ["path", "old_str", "new_str"]}},
]

AGENT_INSTRUCTIONS = """
You are a terminal coding agent in an ongoing session. Every applied
write is checkpointed in git automatically, and the user can type
/undo to revert the most recent change — you don't need to manage
this yourself, just mention it's available if a change turns out wrong.
 
Before any mutating action, call `plan` first. Verify writes worked
before declaring the task done.
"""


def run_agent_turn(input_list: list, max_turns: int = 12) -> list:
    for turn in range(max_turns):
        response = client.responses.create(
            model=CONFIG["model"],
            tools=tools,
            input=input_list,
            instructions=AGENT_INSTRUCTIONS,
        )
        USAGE.add_usage(response.usage.input_tokens, response.usage.output_tokens)
        input_list += response.output

        calls = [item for item in response.output if item.type == "function_call"]
        if not calls:
            print(f"\nagent> {response.output_text}")
            return input_list

        for item in calls:
            args = json.loads(item.arguments)
            label = "..." if item.name == "plan" else args
            print(f"[turn {turn}] {item.name}({label})")
            output = TOOL_IMPL[item.name](args)
            input_list.append({
                "type": "function_call_output",
                "call_id": item.call_id,
                "output": output,
            })

    print("[stopped: hit max_turns for this task]")
    return input_list


def repl():
    if not is_git_repo():
        print("Git not found")
        return

    if not docker_available():
        print("Docker not found on PATH — run_command needs it for sandboxing.")
        print("Install Docker and make sure `docker` is runnable, then retry.")
        return

    print(f"Terminal agent ready in {ROOT} (commands sandboxed in {DOCKER_IMAGE})")
    ensure_image_pulled()
    print("Type a task, or 'exit' to quit.\n")

    input_list = []
    while True:
        try:
            task = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not task:
            continue
        if task.lower() in ("exit", "quit"):
            break
        if task == "/undo":
            print(undo_last())
            continue
        if task == "/usage":
            print(USAGE.summary())
            continue
        input_list.append({"role": "user", "content": task})
        input_list = run_agent_turn(input_list)


if __name__ == "__main__":
    import sys
    if "--init-config" in sys.argv:
        init_config()
    else:
        repl()