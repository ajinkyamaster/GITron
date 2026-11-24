from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import pathlib
import socket
import subprocess
import time
import urllib.parse
from zoneinfo import ZoneInfo

from .core import GITronError, commits, connect, data_root, now_iso, project


def git(*args: str, cwd: pathlib.Path | None = None, timeout: int = 45,
        extra_env: dict[str, str] | None = None) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    if extra_env:
        env.update(extra_env)
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
               *(["-C", str(cwd)] if cwd else []), *args]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise GITronError("Git command timed out") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        # Git can echo a remote URL. Never return a URL containing credentials.
        raise GITronError((detail or "Git operation failed")[:500])
    return result.stdout.strip()


def wait_for_network(remote: str, timeout: float = 30) -> None:
    """Wait for the configured network endpoint; local bare remotes need no probe."""
    if remote.startswith("https://"):
        host, port = urllib.parse.urlsplit(remote).hostname, 443
    elif remote.startswith("git@github.com:"):
        host, port = "github.com", 22
    else:
        return
    deadline = time.monotonic() + timeout
    delay = 1.0
    while True:
        try:
            with socket.create_connection((host, port), timeout=min(3.0, max(0.1, deadline - time.monotonic()))):
                return
        except OSError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GITronError(f"Network endpoint {host}:{port} is unavailable") from exc
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, 15.0)


def _remote_head(repo: pathlib.Path, branch: str, auth_env: dict[str, str]) -> str | None:
    output = git("ls-remote", "origin", f"refs/heads/{branch}", cwd=repo, extra_env=auth_env)
    return output.split()[0] if output else None


def verify_remote(project_id: str) -> dict:
    """Compare the branch head with GITron's last push or adopted fast-forward."""
    from .auth import environment
    with connect() as db:
        item = project(db, project_id)
        rows = commits(db, project_id)
        pushed = [row for row in rows if row["status"] == "PUSHED"]
        expected_sha = _recorded_remote_head(db, project_id, pushed[-1]) if pushed else None
    if not item["remote"]:
        raise GITronError("Set a remote before verifying pushes")
    wait_for_network(item["remote"])
    output = git("ls-remote", item["remote"], f"refs/heads/{item['branch']}",
                 extra_env=environment(project_id, item["remote"]))
    remote_sha = output.split()[0] if output else None
    return {"project_id": project_id, "branch": item["branch"], "remote_sha": remote_sha,
            "last_pushed_sha": pushed[-1]["sha"] if pushed else None,
            "expected_remote_sha": expected_sha, "matches": remote_sha == expected_sha,
            "pushed_commits": len(pushed), "total_commits": len(rows)}


def _recorded_remote_head(db, project_id: str, pushed_row: dict) -> str:
    """An explicitly adopted fast-forward may follow the last GITron commit."""
    adoption = db.execute("""SELECT sha FROM execution_logs
                             WHERE project_id=? AND commit_id=? AND outcome='ADOPTED_REMOTE'
                             ORDER BY id DESC LIMIT 1""", (project_id, pushed_row["id"])).fetchone()
    return adoption[0] if adoption else pushed_row["sha"]


def adopt_remote_fast_forward(project_id: str) -> dict:
    """Accept a descendant remote head only when it adds frozen-plan files."""
    from .auth import environment
    with (data_root() / "worker.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GITronError("The worker is running; retry remote adoption when it finishes") from exc
        with connect() as db:
            item = project(db, project_id)
            rows = commits(db, project_id)
            pushed = [row for row in rows if row["status"] == "PUSHED"]
            if not pushed or not any(row["status"] != "PUSHED" for row in rows):
                raise GITronError("Remote adoption requires a pushed commit and remaining planned commits")
            previous = _recorded_remote_head(db, project_id, pushed[-1])
            repo = _repo_for(item)
            if git("status", "--porcelain", cwd=repo):
                raise GITronError("GITron's local repository has uncommitted changes")
            local = _local_head(repo)
            auth_env = environment(project_id, item["remote"])
            wait_for_network(item["remote"])
            remote = _remote_head(repo, item["branch"], auth_env)
            if not remote or remote == previous:
                raise GITronError("There is no newer remote commit to adopt")
            if local not in {previous, remote}:
                raise GITronError("GITron's local head differs from its recorded remote head")
            git("fetch", "origin", f"refs/heads/{item['branch']}", cwd=repo, extra_env=auth_env)
            fetched = git("rev-parse", "FETCH_HEAD", cwd=repo)
            if fetched != remote or git("merge-base", previous, fetched, cwd=repo) != previous:
                raise GITronError("Remote history is not a stable fast-forward of GITron's last recorded head")
            final_manifest = json.loads((data_root() / "projects" / project_id / "source_manifest.json").read_text())["files"]
            changed = git("diff", "--name-status", "--no-renames", previous, fetched, cwd=repo)
            added = []
            for line in changed.splitlines():
                status, _, path = line.partition("\t")
                if status != "A" or path not in final_manifest:
                    raise GITronError("Remote merge changes an existing or unplanned file: " + path)
                added.append(path)
            if not added:
                raise GITronError("Remote merge adds no files from the frozen project")
            if local == previous:
                git("merge", "--ff-only", "FETCH_HEAD", cwd=repo)
            db.execute("""INSERT INTO execution_logs(project_id,commit_id,attempted_at,outcome,sha,detail)
                          VALUES (?,?,?,?,?,?)""",
                       (project_id, pushed[-1]["id"], now_iso(), "ADOPTED_REMOTE", fetched,
                        "Accepted external fast-forward adding: " + ", ".join(added)))
            db.commit()
            return {"project_id": project_id, "previous_sha": previous,
                    "remote_sha": fetched, "added_files": added}


def remote_conflict_message(branch: str, expected: str | None, actual: str | None) -> str:
    """Explain a branch-head mismatch without confusing it with a branch-name mismatch."""
    if expected is None and actual:
        return (f"Remote branch {branch} already has commit {actual[:12]}, but this plan has not "
                "pushed any commits. Use an empty branch or repository; GITron will not overwrite this history.")
    if expected and actual:
        return (f"Remote branch {branch} is at {actual[:12]}, while GITron last pushed "
                f"{expected[:12]}. Review the remote history before resuming.")
    return (f"Remote branch {branch} is missing, while GITron last pushed "
            f"{expected[:12] if expected else 'no commits'}. Review the remote history before resuming.")


def _notify(message: str, critical: bool = False) -> None:
    try:
        subprocess.run(["notify-send", "-u", "critical" if critical else "normal", "GITron", message],
                       timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _repo_for(item: dict) -> pathlib.Path:
    repo = data_root() / "repos" / item["id"]
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        git("init", "-b", item["branch"], str(repo))
        git("remote", "add", "origin", item["remote"], cwd=repo)
    configured = git("remote", "get-url", "origin", cwd=repo)
    if configured != item["remote"]:
        raise GITronError("Repository remote differs from active plan")
    return repo


def _local_head(repo: pathlib.Path) -> str | None:
    result = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def _last_known_sha(db, project_id: str, rows: list[dict], before_sequence: int) -> str | None:
    for row in reversed(rows[:before_sequence]):
        if row["sha"]:
            return _recorded_remote_head(db, project_id, row)
    return None


def _materialize(repo: pathlib.Path, project_id: str, actions: list[dict]) -> None:
    blob_root = data_root() / "projects" / project_id / "blobs"
    import hashlib
    for action in actions:
        digest = action["blob"]
        path = pathlib.PurePosixPath(action["path"])
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise GITronError("Invalid stored action path")
        target = repo.joinpath(*path.parts)
        if action["type"] == "DELETE":
            target.unlink(missing_ok=True)
        else:
            content = (blob_root / digest).read_bytes()
            if hashlib.sha256(content).hexdigest() != digest:
                raise GITronError("Stored snapshot failed integrity check")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o755 if action.get("executable") else 0o644)
        git("add", "-f", "--", action["path"], cwd=repo)


def _matches_unrecorded_commit(repo: pathlib.Path, row: dict, expected: str | None) -> bool:
    """Identify a commit made just before a crash without public tracking trailers."""
    if git("log", "-1", "--format=%P", cwd=repo) != (expected or ""):
        return False
    expected_message = row["message"] + ("\n\n" + row.get("body", "") if row.get("body") else "")
    if git("log", "-1", "--format=%B", cwd=repo) != expected_message:
        return False
    changed = set(git("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", "HEAD", cwd=repo).splitlines())
    if changed != {action["path"] for action in row["actions"]}:
        return False
    for action in row["actions"]:
        if action["type"] == "DELETE":
            if git("ls-tree", "HEAD", "--", action["path"], cwd=repo):
                return False
            continue
        result = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{action['path']}"], capture_output=True)
        import hashlib
        if result.returncode or hashlib.sha256(result.stdout).hexdigest() != action["blob"]:
            return False
    return True


def _sync_one(db, item: dict, rows: list[dict], row: dict, repo: pathlib.Path, catchup: bool) -> str:
    from .auth import environment
    branch = item["branch"]
    expected = _last_known_sha(db, item["id"], rows, row["sequence"])
    auth_env = environment(item["id"], item["remote"])
    wait_for_network(item["remote"])
    remote = _remote_head(repo, branch, auth_env)
    if row["status"] == "COMMITTED" and remote == row["sha"]:
        db.execute("UPDATE commits SET status='PUSHED', processing_state='', pushed_at=?, catchup=?, error=NULL, attempts=0, retry_after=NULL WHERE id=?",
                   (now_iso(), int(catchup), row["id"]))
        db.commit()
        return row["sha"]
    if remote != expected:
        db.execute("UPDATE projects SET status='PAUSED' WHERE id=?", (item["id"],))
        db.commit()
        raise GITronError(remote_conflict_message(branch, expected, remote))
    local = _local_head(repo)
    if row["status"] == "COMMITTED":
        if local != row["sha"]:
            raise GITronError("Local committed SHA differs from database")
    else:
        if local != expected:
            # A crash may have occurred after git commit but before the DB write.
            if local and _matches_unrecorded_commit(repo, row, expected):
                db.execute("UPDATE commits SET status='COMMITTED', sha=?, error=NULL WHERE id=?", (local, row["id"]))
                db.commit()
            else:
                raise GITronError("Local repository head differs from database")
        else:
            if git("status", "--porcelain", cwd=repo):
                # This repository is owned solely by GITron. Restore a commit
                # interrupted after materialization but before git commit.
                if local:
                    git("reset", "--hard", "HEAD", cwd=repo)
                else:
                    git("rm", "-r", "--cached", "--ignore-unmatch", ".", cwd=repo)
                git("clean", "-fd", cwd=repo)
            _materialize(repo, item["id"], row["actions"])
            if not git("diff", "--cached", "--name-only", cwd=repo):
                raise GITronError("Planned commit contains no file changes")
            commit_args = ["-c", "commit.gpgsign=false", "commit", "-m", row["message"]]
            if row.get("body"):
                commit_args.extend(("-m", row["body"]))
            git(*commit_args, cwd=repo,
                extra_env={"GIT_AUTHOR_DATE": row["scheduled_at"],
                           "GIT_COMMITTER_DATE": row["scheduled_at"]})
            local = _local_head(repo)
            db.execute("UPDATE commits SET status='COMMITTED', sha=?, error=NULL WHERE id=?", (local, row["id"]))
            db.commit()
    git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=repo, timeout=90, extra_env=auth_env)
    if _remote_head(repo, branch, auth_env) != local:
        raise GITronError("Push returned success, but remote head could not be verified")
    db.execute("UPDATE commits SET status='PUSHED', processing_state='', pushed_at=?, catchup=?, error=NULL, attempts=0, retry_after=NULL WHERE id=?",
               (now_iso(), int(catchup), row["id"]))
    db.commit()
    if not catchup:
        _notify(f"Day {row['day']} pushed: {row['message']} ({local[:8]})")
    return local


def run_due(project_id: str | None = None, *, force_next: bool = False) -> list[dict]:
    """Replay all due commits in order using their approved scheduled Git dates."""
    root = data_root()
    lock_path = root / "worker.lock"
    results = []
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GITronError("Another worker is already running") from exc
        with connect() as db:
            ids = [project_id] if project_id else [row[0] for row in db.execute("SELECT id FROM projects WHERE status='ACTIVE'")]
            for pid in ids:
                item = project(db, pid)
                if item["status"] != "ACTIVE":
                    continue
                db.execute("UPDATE commits SET processing_state='' WHERE project_id=? AND processing_state='CATCH_UP'", (pid,))
                db.commit()
                rows = commits(db, pid)
                pending = [row for row in rows if row["status"] != "PUSHED"]
                if not pending:
                    db.execute("UPDATE projects SET status='COMPLETED' WHERE id=?", (pid,))
                    db.commit()
                    continue
                repo = None
                caught_up = 0
                for row in pending:
                    scheduled = dt.datetime.fromisoformat(row["scheduled_at"])
                    due = scheduled <= dt.datetime.now(dt.timezone.utc)
                    if not due and not (force_next and row == pending[0]):
                        break
                    if (row["retry_after"] and not force_next and
                            dt.datetime.fromisoformat(row["retry_after"]) > dt.datetime.now(dt.timezone.utc)):
                        break
                    try:
                        if repo is None:
                            repo = _repo_for(item)
                        catchup = scheduled.astimezone(ZoneInfo(item["timezone"])).date() < dt.datetime.now(ZoneInfo(item["timezone"])).date()
                        if catchup:
                            db.execute("UPDATE commits SET processing_state='CATCH_UP' WHERE id=?", (row["id"],))
                            db.commit()
                        sha = _sync_one(db, item, rows, row, repo, catchup)
                        row["sha"] = sha
                        row["status"] = "PUSHED"
                        db.execute("INSERT INTO execution_logs(project_id,commit_id,attempted_at,outcome,sha) VALUES (?,?,?,?,?)",
                                   (pid, row["id"], now_iso(), "CATCH_UP" if catchup else "PUSHED", sha))
                        db.commit()
                        caught_up += int(catchup)
                        results.append({"project_id": pid, "commit_id": row["id"], "sha": sha, "catchup": catchup})
                        if force_next:
                            break
                    except (GITronError, OSError, subprocess.SubprocessError) as exc:
                        db.execute("UPDATE commits SET processing_state='' WHERE id=?", (row["id"],))
                        if project(db, pid)["status"] == "ACTIVE":
                            attempts = row["attempts"] + 1
                            delay = min(3600, 30 * (2 ** min(attempts - 1, 7)))
                            retry_after = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=delay)).isoformat()
                            db.execute("""UPDATE commits SET status=CASE WHEN sha IS NULL THEN 'FAILED' ELSE 'COMMITTED' END,
                                          processing_state='', error=?, attempts=?, retry_after=? WHERE id=?""",
                                       (str(exc)[:500], attempts, retry_after, row["id"]))
                            db.commit()
                        db.execute("INSERT INTO execution_logs(project_id,commit_id,attempted_at,outcome,sha,detail) VALUES (?,?,?,?,?,?)",
                                   (pid, row["id"], now_iso(), "FAILED", row["sha"], str(exc)[:500]))
                        db.commit()
                        _notify(f"Commit {row['id']} failed: {exc}", critical=True)
                        break
                if caught_up:
                    _notify(f"Caught up {caught_up} scheduled commit{'s' if caught_up != 1 else ''} for {item['name']}")
                if all(row["status"] == "PUSHED" for row in commits(db, pid)):
                    db.execute("UPDATE projects SET status='COMPLETED' WHERE id=?", (pid,))
                    db.commit()
    return results
