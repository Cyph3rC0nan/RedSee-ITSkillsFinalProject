# engine/env.py
"""
Process-entry-point .env loader.

load_scope_config() / load_llm_config() (engine/scope.py, engine/llm.py) read
configuration straight from os.environ — they never touch .env themselves.
load_env() is what populates os.environ from the repo-root .env file, so a
plain `python3 engine/agent.py` / `python app.py` / `python integration.py`
works without an operator having to `source .env` first.

Call load_env() ONLY at a true process entry point (a script's
`if __name__ == "__main__":` block, or app.py's module level before Flask
reads config) — never inside a library module's import path. Importing
engine.scope / engine.llm / engine.sandbox / engine.agent as a library must
never have this side effect.
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _REPO_ROOT / ".env"


def load_env() -> None:
    """Populate os.environ from .env, without overriding already-set vars.

    override=False is mandatory: a variable an operator has explicitly
    exported always wins over the .env file. Idempotent and safe to call more
    than once. Degrades to a silent no-op if python-dotenv isn't installed or
    .env doesn't exist — the pipeline still runs on real exported env vars or
    a manually-sourced .env.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(dotenv_path=_ENV_PATH, override=False)
