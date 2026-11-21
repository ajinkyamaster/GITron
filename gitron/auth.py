"""Per-project GitHub HTTPS credentials held by the user's OS keyring."""

from __future__ import annotations

import os
import atexit
import pathlib
import shlex
import sys
import tempfile

from .core import GITronError, data_root


SERVICE = "GITron GitHub HTTPS"
LLM_SERVICE = "GITron model provider"


def _keyring():
    try:
        import keyring
    except ImportError as exc:
        raise GITronError("Install the keyring package to store a GitHub token") from exc
    return keyring


def set_token(project_id: str, token: str) -> None:
    if not token or any(character.isspace() for character in token):
        raise GITronError("Enter a valid token without spaces")
    try:
        _keyring().set_password(SERVICE, project_id, token)
    except Exception as exc:
        raise GITronError("The OS keyring could not store the GitHub token") from exc


def has_token(project_id: str) -> bool:
    try:
        return bool(_keyring().get_password(SERVICE, project_id) or os.environ.get("GITRON_GITHUB_TOKEN"))
    except Exception:
        return bool(os.environ.get("GITRON_GITHUB_TOKEN"))


def forget_token(project_id: str) -> None:
    """Best effort cleanup of a deleted project's keyring credential."""
    try:
        keyring = _keyring()
        if keyring.get_password(SERVICE, project_id):
            keyring.delete_password(SERVICE, project_id)
    except Exception:
        # A headless session can lack access to the user's keyring. The plan
        # and its blobs are deleted regardless; no token is stored in SQLite.
        pass


def provider_key(provider: str) -> str:
    try:
        return _keyring().get_password(LLM_SERVICE, provider) or ""
    except Exception:
        return ""


def set_provider_key(provider: str, key: str) -> None:
    if not key or any(character.isspace() for character in key):
        raise GITronError("Enter a provider key without spaces")
    try:
        _keyring().set_password(LLM_SERVICE, provider, key)
    except Exception as exc:
        raise GITronError("OS keyring unavailable; use the session key field or provider environment variable") from exc


def askpass() -> None:
    project_id = os.environ.get("GITRON_ASKPASS_PROJECT_ID", "")
    prompt = " ".join(sys.argv[2:]).lower()
    if not project_id:
        raise SystemExit(1)
    if "username" in prompt:
        print("x-access-token")
        return
    if "password" in prompt:
        try:
            token = _keyring().get_password(SERVICE, project_id)
        except Exception:
            token = None
        token = token or os.environ.get("GITRON_GITHUB_TOKEN")
        if token:
            print(token)
            return
    raise SystemExit(1)


def environment(project_id: str, remote: str) -> dict[str, str]:
    if not remote.startswith("https://github.com/") or not has_token(project_id):
        return {}
    # This executable contains only an interpreter command. The token is read
    # from the keyring by a separate process when Git asks for a password.
    fd, filename = tempfile.mkstemp(prefix="askpass-", dir=data_root())
    path = pathlib.Path(filename)
    command = "auth-askpass" if getattr(sys, "frozen", False) else "-m gitron.auth askpass"
    body = f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {command} \"$@\"\n"
    with os.fdopen(fd, "w") as script:
        script.write(body)
    path.chmod(0o700)
    atexit.register(path.unlink, missing_ok=True)
    return {"GIT_ASKPASS": str(path), "GITRON_ASKPASS_PROJECT_ID": project_id}


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "askpass":
    askpass()
