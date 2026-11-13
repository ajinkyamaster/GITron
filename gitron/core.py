from __future__ import annotations

import ast
import base64
import csv
import datetime as dt
import fcntl
import hashlib
import io
import json
import math
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
import zipfile
from collections import defaultdict
from zoneinfo import ZoneInfo

from .syntax import LANGUAGES


SKIP_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".cache"}
SKIP_NAMES = {".env", ".DS_Store"}
SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_SINGLE_FILE = 100 * 1024 * 1024
MAX_FILES = 100_000
MAX_ZIP_ENTRIES = 300_000
UTC = dt.timezone.utc


class GITronError(ValueError):
    pass


def valid_commit_subject(value: object, *, require_scope: bool = False) -> bool:
    """Apply the same Conventional Commit gate to generated and edited plans."""
    if not isinstance(value, str) or len(value) > 72 or "\n" in value:
        return False
    match = re.fullmatch(r"(feat|fix|docs|test|refactor|chore|build|ci|perf)(?:\(([a-z0-9][a-z0-9-]{0,29})\))?: (.+)", value)
    if not match or (require_scope and not match.group(2)):
        return False
    if match.group(2) in {"code", "file", "module", "project", "group", "app"}:
        return False
    return not re.search(r"(?i)\b(?:update code|add file|add group|initial implementation|implement module|misc changes)\b", match.group(3))


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def data_root() -> pathlib.Path:
    root = pathlib.Path(os.environ.get("GITRON_DATA_DIR", pathlib.Path.home() / ".local/share/gitron"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(data_root() / "gitron.sqlite3", timeout=5, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, remote TEXT NOT NULL DEFAULT '',
        branch TEXT NOT NULL DEFAULT 'main', start_date TEXT NOT NULL,
        timezone TEXT NOT NULL, days INTEGER NOT NULL, working_days TEXT NOT NULL DEFAULT '[0,1,2,3,4,5,6]',
        status TEXT NOT NULL DEFAULT 'DRAFT',
        created_at TEXT NOT NULL, workflow TEXT NOT NULL, warnings TEXT NOT NULL,
        workflow_sections TEXT NOT NULL DEFAULT '[]', rest_days TEXT NOT NULL DEFAULT '[]',
        calendar_options TEXT NOT NULL DEFAULT '{}', analysis_stats TEXT NOT NULL DEFAULT '{}',
        CHECK (status IN ('DRAFT','ACTIVE','PAUSED','COMPLETED'))
      );
      CREATE TABLE IF NOT EXISTS commits (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id),
        sequence INTEGER NOT NULL, day INTEGER NOT NULL, scheduled_at TEXT NOT NULL,
        phase TEXT NOT NULL, message TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', actions TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING', sha TEXT, pushed_at TEXT, error TEXT,
        attempts INTEGER NOT NULL DEFAULT 0, retry_after TEXT,
        catchup INTEGER NOT NULL DEFAULT 0,
        processing_state TEXT NOT NULL DEFAULT '',
        UNIQUE(project_id, sequence),
        CHECK (status IN ('PENDING','COMMITTED','PUSHED','FAILED'))
      );
      CREATE INDEX IF NOT EXISTS commits_due ON commits(project_id,status,scheduled_at);
      CREATE TABLE IF NOT EXISTS execution_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id TEXT NOT NULL REFERENCES projects(id),
        commit_id INTEGER NOT NULL REFERENCES commits(id),
        attempted_at TEXT NOT NULL, outcome TEXT NOT NULL,
        sha TEXT, detail TEXT
      );
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(commits)")}
    if "attempts" not in columns:
        db.execute("ALTER TABLE commits ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
    if "retry_after" not in columns:
        db.execute("ALTER TABLE commits ADD COLUMN retry_after TEXT")
    if "catchup" not in columns:
        db.execute("ALTER TABLE commits ADD COLUMN catchup INTEGER NOT NULL DEFAULT 0")
    if "body" not in columns:
        db.execute("ALTER TABLE commits ADD COLUMN body TEXT NOT NULL DEFAULT ''")
    if "processing_state" not in columns:
        db.execute("ALTER TABLE commits ADD COLUMN processing_state TEXT NOT NULL DEFAULT ''")
    project_columns = {row[1] for row in db.execute("PRAGMA table_info(projects)")}
    if "working_days" not in project_columns:
        db.execute("ALTER TABLE projects ADD COLUMN working_days TEXT NOT NULL DEFAULT '[0,1,2,3,4,5,6]'")
    for column, default in (("workflow_sections", "[]"), ("rest_days", "[]"),
                            ("calendar_options", "{}"), ("analysis_stats", "{}")):
        if column not in project_columns:
            db.execute(f"ALTER TABLE projects ADD COLUMN {column} TEXT NOT NULL DEFAULT '{default}'")
    return db


def now_iso() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


def _safe_member(name: str) -> pathlib.PurePosixPath:
    if "\\" in name or "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise GITronError(f"Unsafe archive path: {name!r}")
    path = pathlib.PurePosixPath(name)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise GITronError(f"Unsafe archive path: {name!r}")
    return path


def _ignored(path: pathlib.PurePosixPath) -> bool:
    if path.name in {".env.example", ".env.sample", ".env.template"}:
        return bool(SKIP_PARTS.intersection(path.parts))
    return bool(SKIP_PARTS.intersection(path.parts) or path.name in SKIP_NAMES or
                path.name.startswith(".env.") or path.name in {"id_rsa", "id_ed25519"} or
                path.suffix.lower() in SECRET_SUFFIXES)


SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{32,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
)
DATABASE_CREDENTIAL = re.compile(
    rb"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
    rb"(?P<user>[^\s/@:]+):(?P<password>[^\s/@]+)@(?P<host>[^\s/:]+)"
)
SECRET_ASSIGNMENT = re.compile(
    rb"(?i)\b(?:api[_-]?key|secret|access[_-]?token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_+/=-]{24,200})")


def _check_content_secrets(name: str, content: bytes) -> None:
    if any(pattern.search(content) for pattern in SECRET_PATTERNS):
        raise GITronError(f"Potential credential in {name}; remove it before creating a plan")
    for match in DATABASE_CREDENTIAL.finditer(content):
        # Documentation commonly shows this exact nonfunctional example URL.
        # Keep rejecting URLs with an actual user, password, or host.
        example = (match.group("user").lower(), match.group("password").lower(),
                   match.group("host").lower())
        if example in {(b"user", b"pass", b"host"),
                       (b"username", b"password", b"host")}:
            continue
        raise GITronError(f"Potential credential in {name}; remove it before creating a plan")
    for match in SECRET_ASSIGNMENT.finditer(content):
        value = match.group(1)
        counts = {byte: value.count(byte) for byte in set(value)}
        entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
        if entropy >= 3.8:
            raise GITronError(f"Potential high-entropy credential in {name}; remove it before creating a plan")


def _check_large_archive_resources(total: int, largest: int, target: pathlib.Path) -> None:
    """Avoid starting an in-memory replay that is likely to exhaust this machine."""
    if total <= 256 * 1024 * 1024:
        return
    try:
        available = next(
            int(line.split()[1]) * 1024 for line in pathlib.Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:")
        )
    except (OSError, StopIteration, ValueError, IndexError):
        available = None
    needed_memory = 2 * total + 4 * largest + 512 * 1024 * 1024
    if available is not None and available < needed_memory:
        raise GITronError(
            f"Large project needs about {needed_memory // (1024 ** 2)} MiB free RAM; "
            f"this machine currently has {available // (1024 ** 2)} MiB"
        )
    storage = target.parent
    while not storage.exists():
        storage = storage.parent
    scratch = pathlib.Path(tempfile.gettempdir())
    data_needed = 4 * total + 256 * 1024 * 1024
    scratch_needed = 2 * total + 256 * 1024 * 1024
    if shutil.disk_usage(storage).free < data_needed:
        raise GITronError(f"Large project needs about {data_needed // (1024 ** 2)} MiB free project storage")
    if storage.stat().st_dev != scratch.stat().st_dev and shutil.disk_usage(scratch).free < scratch_needed:
        raise GITronError(f"Large project needs about {scratch_needed // (1024 ** 2)} MiB free temporary storage")


def extract_archive(blob: bytes | pathlib.Path, target: pathlib.Path) -> tuple[dict[str, bytes], list[str], set[str]]:
    archive_size = len(blob) if isinstance(blob, bytes) else pathlib.Path(blob).stat().st_size
    if archive_size > MAX_ARCHIVE:
        raise GITronError(f"ZIP exceeds the {MAX_ARCHIVE // (1024 * 1024)} MiB compressed limit")
    files: dict[str, bytes] = {}
    skipped: list[str] = []
    executable: set[str] = set()
    total = 0
    seen: set[str] = set()
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob) if isinstance(blob, bytes) else blob)
    except zipfile.BadZipFile as exc:
        raise GITronError("Invalid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise GITronError("ZIP has too many entries, including excluded vendor and build files")
        retained_infos = [info for info in infos
                          if not info.is_dir() and not _ignored(_safe_member(info.filename))]
        retained_total = sum(info.file_size for info in retained_infos)
        if retained_total > MAX_EXPANDED:
            raise GITronError(f"Retained source expands beyond the {MAX_EXPANDED // (1024 * 1024)} MiB project limit")
        if len(retained_infos) > MAX_FILES:
            raise GITronError("ZIP contains too many retained source files")
        oversized = next((info for info in retained_infos if info.file_size > MAX_SINGLE_FILE), None)
        if oversized is not None:
            raise GITronError(f"{oversized.filename} exceeds the 100 MiB regular Git file limit; remove it or use Git LFS outside GITron")
        if retained_infos:
            _check_large_archive_resources(retained_total, max(info.file_size for info in retained_infos), target)
        for info in infos:
            path = _safe_member(info.filename)
            mode = info.external_attr >> 16
            if (mode & 0o170000) == 0o120000:
                raise GITronError(f"Symlink rejected: {path}")
            if (mode & 0o170000) not in {0, 0o100000, 0o040000}:
                raise GITronError(f"Special archive file rejected: {path}")
            if info.is_dir():
                continue
            key = str(path).casefold()
            if key in seen:
                raise GITronError(f"Duplicate archive path: {path}")
            seen.add(key)
            if info.flag_bits & 1:
                raise GITronError("Encrypted ZIP entries are unsupported")
            if _ignored(path):
                skipped.append(str(path))
                continue
            if len(files) >= MAX_FILES:
                raise GITronError("ZIP contains too many retained source files")
            total += info.file_size
            if total > MAX_EXPANDED:
                raise GITronError(f"Retained source expands beyond the {MAX_EXPANDED // (1024 * 1024)} MiB project limit")
            if info.file_size > MAX_SINGLE_FILE:
                raise GITronError(f"{path} exceeds the 100 MiB regular Git file limit; remove it or use Git LFS outside GITron")
            if info.file_size > 1024 * 1024 and info.file_size > 1000 * max(info.compress_size, 1):
                raise GITronError("Suspicious ZIP compression ratio")
            content = archive.read(info)
            _check_content_secrets(str(path), content)
            if path.name == ".gitattributes" and re.search(rb"(?:^|\s)filter(?:=|\s|$)", content, re.M):
                raise GITronError("Git filter attributes are unsupported in an archive replay")
            files[str(path)] = content
            if mode & 0o111:
                executable.add(str(path))
    if not files:
        raise GITronError("Archive contains no usable files")
    target.mkdir(parents=True, exist_ok=False)
    for name, content in files.items():
        output = target.joinpath(*pathlib.PurePosixPath(name).parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(content)
        output.chmod(0o755 if name in executable else 0o644)
    return files, skipped, executable


def parse_workflow(pdf: bytes) -> tuple[list[str], list[str]]:
    from .workflow import extract_workflow
    try:
        sections, warnings = extract_workflow(pdf)
    except ValueError as exc:
        raise GITronError(str(exc)) from exc
    return [section["title"] for section in sections], warnings


def _python_dependencies(name: str, content: bytes, all_files: set[str]) -> set[str]:
    from .syntax import MAX_AST_BYTES
    if len(content) > MAX_AST_BYTES:
        prefix = content[:MAX_AST_BYTES].decode("utf-8", "replace")
        imports = re.findall(r"(?m)^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))", prefix)
        modules = {path.removesuffix("/__init__.py").removesuffix(".py").replace("/", "."): path
                   for path in all_files if path.endswith(".py")}
        return {modules[candidate] for row in imports for imported in row if imported
                for candidate in (imported, imported.split(".")[0])
                if candidate in modules and modules[candidate] != name}
    try:
        tree = ast.parse(content.decode("utf-8"), filename=name)
    except (UnicodeDecodeError, SyntaxError):
        return set()
    module_to_file = {path.removesuffix("/__init__.py").removesuffix(".py").replace("/", "."): path
                      for path in all_files if path.endswith(".py")}
    package = name[:-3].replace("/", ".").split(".")[:-1]
    deps: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[:len(package) - node.level + 1] if node.level else []
            stem = ".".join(base + ([node.module] if node.module else []))
            names = [stem] + [f"{stem}.{alias.name}" for alias in node.names]
        for imported in names:
            for candidate in (imported, imported.split(".")[0]):
                if candidate in module_to_file and module_to_file[candidate] != name:
                    deps.add(module_to_file[candidate])
    return deps


def _script_dependencies(name: str, content: bytes, all_files: set[str], files: dict[str, bytes]) -> set[str]:
    from .syntax import script_specifiers
    deps = set()
    configs = [path for path in files if pathlib.PurePosixPath(path).name == "tsconfig.json"]
    config_name = min(configs, key=len) if configs else None
    try:
        compiler = json.loads(files[config_name]).get("compilerOptions", {}) if config_name else {}
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        compiler = {}
    aliases = compiler.get("paths", {}) if isinstance(compiler, dict) else {}
    base_url = compiler.get("baseUrl", ".") if isinstance(compiler, dict) else "."
    for imported in script_specifiers(name, content):
        stems: list[pathlib.PurePosixPath] = []
        if imported.startswith("."):
            stems.append(pathlib.PurePosixPath(name).parent / imported)
        elif isinstance(aliases, dict):
            for pattern, targets in aliases.items():
                if not isinstance(pattern, str) or not isinstance(targets, list):
                    continue
                prefix, marker, suffix = pattern.partition("*")
                if (not marker and imported == pattern) or (marker and imported.startswith(prefix) and imported.endswith(suffix)):
                    middle = imported[len(prefix):len(imported) - len(suffix) if suffix else None] if marker else ""
                    for target in targets:
                        if isinstance(target, str):
                            configured_root = pathlib.PurePosixPath(config_name).parent if config_name else pathlib.PurePosixPath(".")
                            stems.append(configured_root / str(base_url) / target.replace("*", middle))
        for base in stems:
            parts: list[str] = []
            for part in base.parts:
                if part == "..":
                    if parts:
                        parts.pop()
                elif part not in {".", ""}:
                    parts.append(part)
            stem = "/".join(parts)
            for candidate in (stem, *(stem + suffix for suffix in
                                       (".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"))):
                if candidate in all_files and candidate != name:
                    deps.add(candidate)
                    break
    return deps


def dependency_groups(files: dict[str, bytes], profiles: dict[str, dict] | None = None) -> tuple[list[list[str]], list[str]]:
    names = set(files)
    dependencies = {}
    for name, content in files.items():
        if profiles is not None:
            dependencies[name] = set(profiles[name]["internal_dependencies"])
        elif name.endswith(".py"):
            dependencies[name] = _python_dependencies(name, content, names)
        elif name.endswith((".js", ".jsx", ".ts", ".tsx")):
            dependencies[name] = _script_dependencies(name, content, names, files)
        else:
            dependencies[name] = set()
    # Iterative Kosaraju avoids recursion limits on large source trees.
    finish: list[str] = []
    seen: set[str] = set()
    for root in sorted(names):
        stack = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish.append(node)
                continue
            if node in seen:
                continue
            seen.add(node)
            stack.append((node, True))
            stack.extend((dep, False) for dep in sorted(dependencies[node], reverse=True) if dep not in seen)
    reverse: dict[str, set[str]] = defaultdict(set)
    for name, deps in dependencies.items():
        for dep in deps:
            reverse[dep].add(name)
    components: list[list[str]] = []
    assigned: set[str] = set()
    for root in reversed(finish):
        if root in assigned:
            continue
        group = []
        stack = [root]
        assigned.add(root)
        while stack:
            node = stack.pop()
            group.append(node)
            for neighbor in reverse[node]:
                if neighbor not in assigned:
                    assigned.add(neighbor)
                    stack.append(neighbor)
        components.append(sorted(group))
    owner = {name: i for i, group in enumerate(components) for name in group}
    predecessors = {i: {owner[dep] for name in group for dep in dependencies[name] if owner[dep] != i}
                    for i, group in enumerate(components)}
    result: list[list[str]] = []
    done: set[int] = set()
    while len(done) < len(components):
        ready = [i for i in range(len(components)) if i not in done and predecessors[i] <= done]
        if not ready:
            raise GITronError("Internal dependency graph error")
        def rank(i: int) -> tuple[int, str]:
            name = components[i][0].lower()
            if profiles is not None:
                return (min(profiles[path]["stratum"] for path in components[i]), name)
            leaf = pathlib.PurePosixPath(name).name
            if leaf in {"package.json", "pyproject.toml", "requirements.txt", ".gitignore",
                        "tsconfig.json", "__init__.py", ".env.example", ".env.sample", ".env.template"}:
                return (0, name)
            if any(part in name for part in ("test", "docs", "readme", "docker")):
                return (3, name)
            if any(part in name for part in ("model", "schema", "util", "config")):
                return (1, name)
            return (2, name)
        chosen = min(ready, key=rank)
        result.append(components[chosen])
        done.add(chosen)
    cycles = [", ".join(group) for group in result if len(group) > 1]
    return result, cycles


def _partial_python(name: str, content: bytes, minimum_lines: int = 80) -> list[bytes]:
    from .syntax import MAX_AST_BYTES
    if len(content) > MAX_AST_BYTES:
        return []
    try:
        source = content.decode("utf-8")
        tree = ast.parse(source, filename=name)
    except (UnicodeDecodeError, SyntaxError):
        return []
    declarations = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if len(source.splitlines()) < minimum_lines or len(declarations) < 4:
        return []
    count = len(declarations)
    indices = (sorted({max(1, count // 4), max(2, count // 2), max(3, 3 * count // 4)})
               if count >= 8 else sorted({max(1, count // 3), max(2, 2 * count // 3)})
               if count >= 6 else [count // 2])
    snapshots: list[bytes] = []
    for index in indices:
        cut = declarations[index].lineno
        later = {node.name for node in declarations if node.lineno >= cut}
        if any(any(isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id in later
                   for child in ast.walk(node)) for node in tree.body if node.lineno < cut):
            return snapshots
        partial = "".join(source.splitlines(keepends=True)[:cut - 1]).encode("utf-8")
        try:
            compile(partial, name, "exec")
        except SyntaxError:
            return snapshots
        if partial and partial != content and (not snapshots or partial != snapshots[-1]):
            snapshots.append(partial)
    return snapshots


def _manifest_partial(name: str, content: bytes) -> bytes | None:
    leaf = pathlib.PurePosixPath(name).name.lower()
    if leaf == "requirements.txt":
        lines = content.splitlines(keepends=True)
        if len(lines) >= 4:
            partial = b"".join(lines[:max(1, len(lines) // 2)])
            return partial if partial != content else None
    if leaf == "package.json":
        try:
            original = json.loads(content)
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(original, dict) and len(original) >= 4:
            base = {key: original[key] for key in ("name", "version", "private", "type") if key in original}
            partial = (json.dumps(base, indent=2) + "\n").encode()
            return partial if partial != content else None
    if leaf == "pyproject.toml":
        try:
            import tomllib
            original = tomllib.loads(content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        project = original.get("project", {})
        poetry = original.get("tool", {}).get("poetry", {})
        metadata = project if isinstance(project, dict) and project.get("name") else poetry
        if isinstance(metadata, dict) and isinstance(metadata.get("name"), str) and len(content.splitlines()) >= 6:
            heading = "[project]" if metadata is project else "[tool.poetry]"
            lines = [heading, f"name = {json.dumps(metadata['name'])}"]
            if isinstance(metadata.get("version"), str):
                lines.append(f"version = {json.dumps(metadata['version'])}")
            partial = ("\n".join(lines) + "\n").encode()
            return partial if partial != content else None
    if leaf.startswith("readme") and leaf.endswith((".md", ".rst")):
        lines = content.splitlines(keepends=True)
        if len(lines) >= 8:
            partial = b"".join(lines[:max(3, len(lines) // 4)])
            return partial if partial != content else None
    return None


def _blob(root: pathlib.Path, content: bytes) -> str:
    digest = hashlib.sha256(content).hexdigest()
    path = root / "blobs" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(content)
    return digest


def _changed_line_counts(root: pathlib.Path, steps: list[tuple[str, list[dict], str]]) -> list[int]:
    import difflib
    state: dict[str, bytes] = {}
    result = []
    for _, actions, _ in steps:
        changed = 0
        for action in actions:
            old = state.get(action["path"], b"")
            new = b"" if action["type"] == "DELETE" else (root / "blobs" / action["blob"]).read_bytes()
            if max(len(old), len(new)) <= 1_000_000:
                old_lines = old.splitlines()
                new_lines = new.splitlines()
                for kind, before_start, before_end, after_start, after_end in difflib.SequenceMatcher(
                        a=old_lines, b=new_lines, autojunk=False).get_opcodes():
                    if kind != "equal":
                        changed += max(before_end - before_start, after_end - after_start)
            else:
                changed += max(1, abs(new.count(b"\n") - old.count(b"\n")),
                               min(new.count(b"\n"), old.count(b"\n")) // 10)
            state[action["path"]] = new
        result.append(max(1, changed))
    return result


def _phase(name: str, milestones: list[str], index: int, total: int) -> str:
    if len(milestones) == 1:
        return milestones[0]
    path = pathlib.PurePosixPath(name)
    leaf = path.name.lower()
    if (leaf in {"package.json", "pyproject.toml", "requirements.txt", ".gitignore",
                 "tsconfig.json", "__init__.py", ".env.example", ".env.sample", ".env.template"}
            or leaf.startswith("config.")):
        return milestones[0]
    if (leaf.startswith(("test_", "spec_")) or leaf.endswith((".test.py", ".test.ts", ".spec.ts"))
            or "tests" in path.parts or "docs" in path.parts or leaf.startswith("readme")):
        return milestones[-1]
    def terms(value: str) -> set[str]:
        words = re.findall(r"[a-z0-9]+", value.lower())
        return {word[:-3] if word.endswith("ing") and len(word) > 6 else
                word[:-1] if word.endswith("s") and len(word) > 4 else word
                for word in words if len(word) > 3}
    file_terms = terms(path.stem)
    scores = [len(file_terms & terms(title)) for title in milestones]
    if max(scores) > 0:
        return milestones[scores.index(max(scores))]
    if any(part in {"web", "ui", "frontend", "client"} for part in path.parts):
        return milestones[-2]
    return milestones[min(len(milestones) - 1, index * len(milestones) // max(total, 1))]


def validate_action_order(files: dict[str, bytes], action_lists: list[list[dict]],
                          profiles: dict[str, dict] | None = None) -> None:
    first: dict[str, int] = {}
    for sequence, actions in enumerate(action_lists):
        for action in actions:
            first.setdefault(action["path"], sequence)
    names = set(files)
    for name, content in files.items():
        deps = (set(profiles[name]["internal_dependencies"]) if profiles is not None else
                _python_dependencies(name, content, names) if name.endswith(".py") else
                _script_dependencies(name, content, names, files) if name.endswith((".js", ".jsx", ".ts", ".tsx")) else set())
        if any(first.get(dep, len(action_lists)) > first.get(name, len(action_lists)) for dep in deps):
            raise GITronError(f"Plan places {name} before an imported dependency")


def verify_git_replay(root: pathlib.Path, steps: list[tuple[str, list[dict], str]], files: dict[str, bytes],
                      executable: set[str]) -> None:
    """Check every step can become a real commit and the final Git tree is exact."""
    with tempfile.TemporaryDirectory(prefix="gitron-verify-") as temp:
        repo = pathlib.Path(temp)
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                   GIT_TERMINAL_PROMPT="0")

        def run(*args: str) -> bytes:
            try:
                return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
                                       "-C", str(repo), *args],
                                      capture_output=True, check=True, timeout=30, env=env).stdout
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise GITronError(f"Dry-run Git replay failed at {' '.join(args[:2])}") from exc

        run("init", "-b", "main")
        for sequence, (_, actions, _) in enumerate(steps):
            for action in actions:
                path = repo.joinpath(*pathlib.PurePosixPath(action["path"]).parts)
                if action["type"] == "DELETE":
                    path.unlink(missing_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    snapshot = (root / "blobs" / action["blob"]).read_bytes()
                    if action["type"] in {"WRITE-PARTIAL", "MODIFY"}:
                        if action["path"].endswith(".py"):
                            try:
                                compile(snapshot, action["path"], "exec")
                            except SyntaxError as exc:
                                raise GITronError(f"Invalid intermediate Python syntax: {action['path']}") from exc
                        elif pathlib.PurePosixPath(action["path"]).suffix.lower() in LANGUAGES:
                            from .syntax import parse_tree
                            tree = parse_tree(action["path"], snapshot)
                            if tree is None or tree.root_node.has_error:
                                raise GITronError(f"Invalid intermediate script syntax: {action['path']}")
                    path.write_bytes(snapshot)
                    path.chmod(0o755 if action.get("executable") else 0o644)
                run("add", "-f", "--", action["path"])
            if not run("diff", "--cached", "--name-only"):
                raise GITronError(f"Dry-run commit {sequence + 1} is empty")
            run("-c", "user.name=GITron Verifier", "-c", "user.email=verify@localhost",
                "-c", "commit.gpgsign=false", "commit", "-m", f"verify step {sequence + 1}")
        tree_names = set(run("ls-tree", "-r", "--name-only", "-z", "HEAD").decode().rstrip("\x00").split("\x00"))
        if tree_names != set(files):
            raise GITronError("Final Git tree file list differs from the sanitized archive")
        for name, content in files.items():
            if run("show", f"HEAD:{name}") != content:
                raise GITronError(f"Final Git tree differs from source: {name}")
            mode = run("ls-tree", "HEAD", "--", name).split(b" ", 1)[0]
            if mode != (b"100755" if name in executable else b"100644"):
                raise GITronError(f"Final Git executable mode differs from source: {name}")


def create_project(name: str, archive: bytes | pathlib.Path, pdf: bytes, start_date: str, days: int,
                   timezone: str, remote: str = "", branch: str = "main", planner: str = "openai",
                   *, api_key: str | None = None, model: str | None = None,
                   working_days: tuple[int, ...] | None = None,
                   rest_weekdays: tuple[int, ...] | None = None,
                   organic_break_days: bool = False,
                   weekday_window: str = "18:30-23:15",
                   weekend_window: str = "10:30-18:30") -> str:
    if not 1 <= days <= 365:
        raise GITronError("Timeline must be between 1 and 365 days")
    try:
        start = dt.date.fromisoformat(start_date)
        zone = ZoneInfo(timezone)
    except (ValueError, KeyError) as exc:
        raise GITronError("Invalid start date or IANA timezone") from exc
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("-") or ".." in branch:
        raise GITronError("Invalid Git branch")
    if planner not in {"openai", "anthropic", "groq", "gemini", "deepseek", "offline"}:
        raise GITronError("Unsupported planning mode")
    from .calendar import calendar_days, parse_window
    try:
        parse_window(weekday_window)
        parse_window(weekend_window)
    except ValueError as exc:
        raise GITronError(str(exc)) from exc
    if rest_weekdays is not None:
        rest_weekdays = tuple(rest_weekdays)
        if len(set(rest_weekdays)) != len(rest_weekdays) or any(type(day) is not int or day not in range(7) for day in rest_weekdays):
            raise GITronError("Rest weekdays must be unique numbers from 0 to 6")
    if working_days is None:
        working_days = tuple(day for day in range(7) if day not in (rest_weekdays if rest_weekdays is not None else (6,)))
    else:
        working_days = tuple(working_days)
        if rest_weekdays is not None and set(working_days) != set(range(7)) - set(rest_weekdays):
            raise GITronError("Working days and rest weekdays disagree")
    if not working_days or len(set(working_days)) != len(working_days) or any(type(day) is not int or day not in range(7) for day in working_days):
        raise GITronError("Working days must be unique weekday numbers from 0 (Monday) to 6 (Sunday)")
    if not any((start + dt.timedelta(days=day - 1)).weekday() in working_days for day in range(1, days + 1)):
        raise GITronError("Timeline has no selected working days")
    validate_remote(remote)
    project_id = uuid.uuid4().hex
    root = data_root() / "projects" / project_id
    files, skipped, executable = extract_archive(archive, root / "raw")
    try:
        from .workflow import extract_workflow
        from .semantics import align_profiles, build_profiles, offline_message
        try:
            sections, warnings = extract_workflow(pdf)
        except ValueError as exc:
            raise GITronError(str(exc)) from exc
        milestones = [section["title"] for section in sections]
        (root / "workflow.pdf").write_bytes(pdf)
        file_seed = json.dumps({path: hashlib.sha256(content).hexdigest() for path, content in sorted(files.items())},
                               sort_keys=True).encode()
        active_days, rest_days = calendar_days(start, days, working_days, organic_break_days, file_seed)
        if not active_days:
            raise GITronError("Calendar contains no active days after selected breaks")
        profiles = build_profiles(files, executable)
        bounded = sum(profile.get("analysis_bounded", False) for profile in profiles.values())
        if bounded:
            warnings.append(f"Bounded structural analysis for {bounded} files over 2 MB; exact source bytes remain in the final replay")
        groups, cycles = dependency_groups(files, profiles)
        warnings += [f"Ignored {len(skipped)} build, vendor, or sensitive files"] if skipped else []
        warnings += [f"Import cycle grouped atomically: {cycle}" for cycle in cycles]
        target_groups = min(len(active_days) * 3, 500)
        if len(groups) > target_groups:
            width = (len(groups) + target_groups - 1) // target_groups
            original_count = len(groups)
            groups = [[name for group in groups[i:i + width] for name in group]
                      for i in range(0, len(groups), width)]
            warnings.append(f"Combined {original_count} dependency groups into {len(groups)} commits to keep the plan usable")
        alignment = align_profiles(profiles, sections, groups)
        (root / "analysis.json").write_text(json.dumps({"sections": sections, "profiles": profiles,
                                                        "alignment": alignment}, ensure_ascii=False))
        recommendations = None
        phase_weights = [section["effort_weight"] for section in sections]
        if planner != "offline":
            from .llm import OpenAIPlanner, ProviderPlanner
            llm = (OpenAIPlanner(api_key=api_key, model=model) if planner == "openai" else
                   ProviderPlanner(planner, api_key=api_key, model=model))
            phase_weights = llm.phase_weights(milestones, len(active_days), len(groups), sections=sections)
            recommendations = llm.plan(groups, files, milestones, days,
                                       sections=sections, profiles=profiles, alignment=alignment)
            if len(recommendations) != len(groups):
                raise GITronError("LLM plan did not cover every dependency group")
            warnings.append(f"AI planning used {planner}/{llm.model}; inspect phase and commit suggestions before activation")
            if getattr(llm, "fallback_count", 0):
                warnings.append(f"Local semantic messages replaced {llm.fallback_count} invalid or duplicate AI commit subjects")
        else:
            warnings.append("Offline planner selected; no LLM analyzed this project")
        phase_by_id = {section["phase_id"]: section["title"] for section in sections}
        section_by_id = {section["phase_id"]: section for section in sections}
        steps: list[tuple[str, list[dict], str]] = []
        deferred: list[tuple[str, list[dict], str]] = []
        used_messages: set[str] = set()
        body_by_message: dict[str, str] = {}
        preseeded: set[str] = set()
        for path in sorted(files):
            if pathlib.PurePosixPath(path).name.lower().startswith("readme"):
                partial = _manifest_partial(path, files[path])
                if partial:
                    preseeded.add(path)
                    action = {"path": path, "type": "WRITE-PARTIAL", "blob": _blob(root, partial),
                              "executable": path in executable}
                    message = offline_message(path, "WRITE-PARTIAL", partial, b"", profiles[path],
                                              used_messages, sections[0])
                    steps.append((milestones[0], [action], message))
        for i, group in enumerate(groups):
            suggestion = recommendations[i] if recommendations is not None else None
            phase = suggestion["phase"] if suggestion else phase_by_id[alignment[group[0]]]
            profile = profiles[group[0]]
            if deferred and profile["stratum"] == 3:
                steps.extend(deferred)
                deferred.clear()
            if len(group) == 1 and group[0] not in preseeded and profile["stratum"] == 0:
                initial = _manifest_partial(group[0], files[group[0]])
                if initial:
                    action = {"path": group[0], "type": "WRITE-PARTIAL", "blob": _blob(root, initial),
                              "executable": group[0] in executable}
                    steps.append((milestones[0], [action], offline_message(
                        group[0], "WRITE-PARTIAL", initial, b"", profile, used_messages, sections[0])))
                    full = {"path": group[0], "type": "CREATE-FULL", "blob": _blob(root, files[group[0]]),
                            "executable": group[0] in executable}
                    deferred.append((phase, [full], offline_message(
                        group[0], "CREATE-FULL", files[group[0]], initial, profile, used_messages,
                        section_by_id[alignment[group[0]]])))
                    continue
            want_partial = (suggestion["split_file"] if suggestion else True) or len(groups) < len(active_days)
            partials: list[bytes] = []
            if len(group) == 1 and want_partial and group[0] not in preseeded:
                if group[0].endswith(".py"):
                    partials = _partial_python(group[0], files[group[0]],
                                               minimum_lines=20 if len(groups) < len(active_days) else 80)
                elif pathlib.PurePosixPath(group[0]).suffix.lower() in LANGUAGES:
                    from .syntax import script_snapshots
                    partials = script_snapshots(group[0], files[group[0]],
                                                minimum_lines=20 if len(groups) < len(active_days) else 80)
            previous = b""
            for part_number, partial in enumerate(partials, 1):
                action_type = "WRITE-PARTIAL" if part_number == 1 else "MODIFY"
                proposed = suggestion.get("stage_messages", []) if suggestion else []
                part_message = proposed[part_number - 1] if len(proposed) >= part_number else ""
                if part_message and part_message not in used_messages:
                    used_messages.add(part_message)
                else:
                    part_message = offline_message(group[0], action_type, partial, previous, profile,
                                                   used_messages, section_by_id[alignment[group[0]]])
                steps.append((phase, [{"path": group[0], "type": action_type,
                                      "blob": _blob(root, partial), "executable": group[0] in executable}], part_message))
                previous = partial
            actions = [{"path": file, "type": "CREATE-FULL",
                        "blob": _blob(root, files[file]), "executable": file in executable} for file in group]
            if suggestion and suggestion.get("message"):
                message = suggestion["message"]
                if message in used_messages or re.search(r"(?i)\b(?:update code|add file|initial implementation of module)\b", message):
                    message = offline_message(group[0], "CREATE-FULL", files[group[0]], previous,
                                              profile, used_messages, section_by_id[alignment[group[0]]])
                else:
                    used_messages.add(message)
                if suggestion.get("body"):
                    body_by_message[message] = suggestion["body"]
            else:
                message = offline_message(group[0], "CREATE-FULL", files[group[0]], previous,
                                          profile, used_messages, section_by_id[alignment[group[0]]])
            steps.append((phase, actions, message))
        steps.extend(deferred)
        if not steps:
            raise GITronError("No project content to schedule")
        if len({message for _, _, message in steps}) != len(steps) or any(
                not valid_commit_subject(message) for _, _, message in steps):
            raise GITronError("Generated commit subjects must be unique Conventional Commits of at most 72 characters")
        final_digests: dict[str, str] = {}
        for _, actions, _ in steps:
            for action in actions:
                final_digests[action["path"]] = action["blob"]
        if final_digests != {path: hashlib.sha256(content).hexdigest() for path, content in files.items()}:
            raise GITronError("Final replay differs from sanitized archive")
        validate_action_order(files, [actions for _, actions, _ in steps], profiles)
        verify_git_replay(root, steps, files, executable)
        if len(steps) < len(active_days):
            warnings.append(f"Only {len(steps)} meaningful content changes for {len(active_days)} working days; remaining days stay empty")
        schedule_input = json.dumps(
            {"files": final_digests, "steps": steps, "start": start_date, "days": days,
             "timezone": timezone, "working_days": working_days},
            sort_keys=True, ensure_ascii=False,
        ).encode()
        # Keep phases in workflow order, then divide selected working days into
        # contiguous phase windows. Dependencies retain their original sequence.
        ordered_steps: list[tuple[str, list[dict], str]] = []
        last_phase = 0
        for phase, actions, message in steps:
            index = milestones.index(phase) if phase in milestones else last_phase
            if index < last_phase:
                warnings.append(f"Moved {phase} to {milestones[last_phase]} to preserve dependency order")
                index = last_phase
            last_phase = index
            ordered_steps.append((milestones[index], actions, message))
        steps = ordered_steps
        phase_count = len(milestones)
        phase_counts = [sum(phase == milestones[index] for phase, _, _ in steps)
                        for index in range(phase_count)]
        target_days = [len(active_days) * weight / sum(phase_weights) for weight in phase_weights]
        phase_days = [0] * phase_count
        # When enough commits exist, never give a phase more working days than
        # commits: that would create avoidable empty days elsewhere.
        capacities = phase_counts if len(steps) >= len(active_days) else [
            len(active_days) if count else 0 for count in phase_counts
        ]
        for _ in active_days:
            eligible = [index for index in range(phase_count) if phase_days[index] < capacities[index]]
            if not eligible:
                break
            chosen = max(eligible, key=lambda index: (target_days[index] - phase_days[index],
                                                      phase_weights[index], -index))
            phase_days[chosen] += 1
        day_numbers: list[int] = []
        cursor = 0
        for phase_index in range(phase_count):
            count = phase_counts[phase_index]
            window = active_days[cursor:cursor + phase_days[phase_index]]
            cursor += phase_days[phase_index]
            if not count:
                continue
            if not window:
                window = [active_days[min(cursor, len(active_days) - 1)]]
            day_numbers.extend(window[round(sequence * (len(window) - 1) / max(count - 1, 1))]
                               for sequence in range(count))
        from .calendar import session_times
        schedule_seed = hashlib.sha256(schedule_input).digest()
        scheduled_times = session_times(start, zone, day_numbers, _changed_line_counts(root, steps),
                                        weekday_window, weekend_window, schedule_seed)
        brief_sections = [{**section, "body_text": section["body_text"][:2500]} for section in sections]
        stats = {"pdf_sections": len(sections), "pdf_words": sum(section["word_count"] for section in sections),
                 "ast_symbols": sum(len(profile["declarations"]) for profile in profiles.values()),
                 "parser_verified_files": sum(profile["parser_verified"] for profile in profiles.values()),
                 "bounded_profiles": bounded,
                 "files": len(files), "ocr_pages": sum("OCR used" in warning for warning in warnings),
                 "active_days": len(active_days), "rest_days": len(rest_days)}
        calendar_options = {"rest_weekdays": sorted(set(range(7)) - set(working_days)),
                            "organic_break_days": bool(organic_break_days),
                            "weekday_window": weekday_window, "weekend_window": weekend_window}
        with connect() as db:
            db.execute("""INSERT INTO projects(id,name,remote,branch,start_date,timezone,days,working_days,status,
                          created_at,workflow,warnings,workflow_sections,rest_days,calendar_options,analysis_stats)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (project_id, name[:120] or "Untitled project", remote, branch, start_date,
                        timezone, days, json.dumps(working_days), "DRAFT", now_iso(),
                        json.dumps(milestones), json.dumps(warnings), json.dumps(brief_sections),
                        json.dumps(rest_days), json.dumps(calendar_options), json.dumps(stats)))
            for sequence, (phase, actions, message) in enumerate(steps):
                day = day_numbers[sequence]
                db.execute("""INSERT INTO commits(project_id,sequence,day,scheduled_at,phase,message,body,actions)
                              VALUES (?,?,?,?,?,?,?,?)""",
                           (project_id, sequence, day, scheduled_times[sequence], phase, message,
                            body_by_message.get(message, ""), json.dumps(actions)))
        return project_id
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def validate_remote(remote: str) -> None:
    if not remote:
        return
    if "\n" in remote or "\r" in remote or remote.startswith("-"):
        raise GITronError("Invalid remote URL")
    if remote.startswith("https://"):
        from urllib.parse import urlsplit
        parts = urlsplit(remote)
        if (parts.username or parts.password or parts.hostname != "github.com" or parts.port or
                parts.query or parts.fragment or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", parts.path)):
            raise GITronError("Use a credential-free GitHub HTTPS URL")
    elif remote.startswith("git@github.com:"):
        if not re.fullmatch(r"git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", remote):
            raise GITronError("Invalid GitHub SSH remote")
    elif pathlib.Path(remote).is_absolute():
        pass  # Useful for private, local bare repositories and tests.
    else:
        raise GITronError("Remote must be GitHub HTTPS, GitHub SSH, or an absolute local path")


def project(db: sqlite3.Connection, project_id: str) -> dict:
    row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if not row:
        raise GITronError("Project not found")
    result = dict(row)
    result["workflow"] = json.loads(result["workflow"])
    result["warnings"] = json.loads(result["warnings"])
    result["working_days"] = json.loads(result["working_days"])
    result["workflow_sections"] = json.loads(result["workflow_sections"])
    result["rest_days"] = json.loads(result["rest_days"])
    result["calendar_options"] = json.loads(result["calendar_options"])
    result["analysis_stats"] = json.loads(result["analysis_stats"])
    return result


def commits(db: sqlite3.Connection, project_id: str) -> list[dict]:
    result = []
    for row in db.execute("SELECT * FROM commits WHERE project_id=? ORDER BY sequence", (project_id,)):
        item = dict(row)
        item["actions"] = json.loads(item["actions"])
        result.append(item)
    return result


def _inside_working_window(when: dt.datetime, timezone: str, options: dict) -> bool:
    from .calendar import parse_window
    local = when.astimezone(ZoneInfo(timezone))
    option = "weekday_window" if local.weekday() < 5 else "weekend_window"
    default = "18:30-23:15" if option == "weekday_window" else "10:30-18:30"
    try:
        begin, finish = parse_window(options.get(option, default))
    except (TypeError, ValueError):
        return False
    return begin <= local.time().replace(tzinfo=None) <= finish


def update_commit(db: sqlite3.Connection, project_id: str, commit_id: int, *, message: str | None = None,
                  scheduled_at: str | None = None, phase: str | None = None) -> None:
    item = project(db, project_id)
    if item["status"] != "DRAFT":
        raise GITronError("Only draft plans can be edited")
    row = db.execute("SELECT * FROM commits WHERE project_id=? AND id=?", (project_id, commit_id)).fetchone()
    if not row:
        raise GITronError("Commit not found")
    if message is not None:
        message = message.strip()
        if not valid_commit_subject(message):
            raise GITronError("Commit message must be a specific Conventional Commit subject of at most 72 characters")
        if db.execute("SELECT 1 FROM commits WHERE project_id=? AND id<>? AND message=?",
                      (project_id, commit_id, message)).fetchone():
            raise GITronError("Commit message already appears in this plan")
        db.execute("UPDATE commits SET message=? WHERE id=?", (message.strip(), commit_id))
    if phase is not None:
        if phase.strip() not in item["workflow"]:
            raise GITronError("Phase must be one of the PDF workflow phases")
        db.execute("UPDATE commits SET phase=? WHERE id=?", (phase.strip(), commit_id))
    if scheduled_at is not None:
        try:
            parsed = dt.datetime.fromisoformat(scheduled_at)
        except ValueError as exc:
            raise GITronError("Invalid timestamp") from exc
        if parsed.tzinfo is None:
            raise GITronError("Timestamp needs UTC offset")
        local_day = parsed.astimezone(ZoneInfo(item["timezone"])).date()
        day = (local_day - dt.date.fromisoformat(item["start_date"])).days + 1
        if day not in range(1, item["days"] + 1) or local_day.weekday() not in item["working_days"] or day in item["rest_days"]:
            raise GITronError("Timestamp must fall on a selected working day in the timeline")
        if not _inside_working_window(parsed, item["timezone"], item["calendar_options"]):
            raise GITronError("Timestamp must fall inside the selected coding window")
        prev = db.execute("SELECT scheduled_at FROM commits WHERE project_id=? AND sequence<? ORDER BY sequence DESC LIMIT 1",
                          (project_id, row["sequence"])).fetchone()
        next_ = db.execute("SELECT scheduled_at FROM commits WHERE project_id=? AND sequence>? ORDER BY sequence LIMIT 1",
                           (project_id, row["sequence"])).fetchone()
        if (prev and parsed <= dt.datetime.fromisoformat(prev[0])) or (next_ and parsed >= dt.datetime.fromisoformat(next_[0])):
            raise GITronError("Schedule must remain in commit order")
        db.execute("UPDATE commits SET scheduled_at=?, day=? WHERE id=?", (parsed.isoformat(), day, commit_id))


def move_commit_day(db: sqlite3.Connection, project_id: str, commit_id: int, day: int) -> None:
    """Move a draft commit to the end of a working day if dependencies still hold."""
    item = project(db, project_id)
    if item["status"] != "DRAFT":
        raise GITronError("Only draft plans can be reordered")
    if type(day) is not int or day not in range(1, item["days"] + 1):
        raise GITronError("Target day is outside the timeline")
    local_date = dt.date.fromisoformat(item["start_date"]) + dt.timedelta(days=day - 1)
    if local_date.weekday() not in item["working_days"] or day in item["rest_days"]:
        raise GITronError("Target day is not a selected working day")
    rows = commits(db, project_id)
    chosen = next((row for row in rows if row["id"] == commit_id), None)
    if chosen is None:
        raise GITronError("Commit not found")
    other = [row for row in rows if row["id"] != commit_id]
    same_day = [dt.datetime.fromisoformat(row["scheduled_at"]) for row in other if row["day"] == day]
    zone = ZoneInfo(item["timezone"])
    from .calendar import parse_window
    option = "weekday_window" if local_date.weekday() < 5 else "weekend_window"
    default = "18:30-23:15" if option == "weekday_window" else "10:30-18:30"
    begin, finish = parse_window(item["calendar_options"].get(option, default))
    window_start = dt.datetime.combine(local_date, begin, tzinfo=zone)
    window_end = dt.datetime.combine(local_date, finish, tzinfo=zone)
    timestamp = (max(same_day) + dt.timedelta(minutes=1) if same_day else
                 window_start + dt.timedelta(minutes=15))
    if timestamp >= window_end or timestamp.astimezone(zone).date() != local_date:
        raise GITronError("No available timestamp remains in that day's coding window")
    chosen["day"] = day
    chosen["scheduled_at"] = timestamp.isoformat()
    ordered = sorted([*other, chosen], key=lambda row: dt.datetime.fromisoformat(row["scheduled_at"]))
    ranks = {"WRITE-PARTIAL": 0, "MODIFY": 1, "CREATE-FULL": 2, "DELETE": 3}
    last_rank: dict[str, int] = {}
    for row in ordered:
        for action in row["actions"]:
            rank = ranks[action["type"]]
            if rank < last_rank.get(action["path"], -1):
                raise GITronError("Move would reverse the stages of a file")
            last_rank[action["path"]] = rank
    raw = data_root() / "projects" / project_id / "raw"
    files = {path.relative_to(raw).as_posix(): path.read_bytes() for path in raw.rglob("*") if path.is_file()}
    from .semantics import build_profiles
    validate_action_order(files, [row["actions"] for row in ordered], build_profiles(files, set()))
    # Move all sequence values out of the unique-index range before reassignment.
    db.execute("UPDATE commits SET sequence=sequence+1000000 WHERE project_id=?", (project_id,))
    for sequence, row in enumerate(ordered):
        db.execute("UPDATE commits SET sequence=?, day=?, scheduled_at=? WHERE id=?",
                   (sequence, row["day"], row["scheduled_at"], row["id"]))


def set_project_state(db: sqlite3.Connection, project_id: str, status: str) -> None:
    current = project(db, project_id)
    allowed = {"DRAFT": {"ACTIVE"}, "ACTIVE": {"PAUSED"}, "PAUSED": {"ACTIVE"}, "COMPLETED": set()}
    if status not in allowed[current["status"]]:
        raise GITronError(f"Cannot change {current['status']} to {status}")
    if status == "ACTIVE" and not current["remote"]:
        raise GITronError("Set a remote before activation")
    db.execute("UPDATE projects SET status=? WHERE id=?", (status, project_id))


def set_remote(db: sqlite3.Connection, project_id: str, remote: str) -> None:
    validate_remote(remote)
    if project(db, project_id)["status"] != "DRAFT":
        raise GITronError("Remote can only be changed in draft")
    db.execute("UPDATE projects SET remote=? WHERE id=?", (remote, project_id))


def delete_project(project_id: str) -> str:
    """Remove one local plan and its snapshots without touching its Git remote."""
    if not re.fullmatch(r"[0-9a-f]{32}", project_id):
        raise GITronError("Invalid project ID")
    root = data_root()
    with (root / "worker.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GITronError("A worker is pushing commits; retry deletion when it finishes") from exc
        with connect() as db:
            item = project(db, project_id)
            db.execute("DELETE FROM execution_logs WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM commits WHERE project_id=?", (project_id,))
            db.execute("DELETE FROM projects WHERE id=?", (project_id,))
        for folder in (root / "projects" / project_id, root / "repos" / project_id):
            if folder.exists():
                shutil.rmtree(folder)
    from .auth import forget_token
    forget_token(project_id)
    return item["name"]


def export_plan(db: sqlite3.Connection, project_id: str, format: str) -> tuple[bytes, str, str]:
    item = project(db, project_id)
    rows = commits(db, project_id)
    if format == "json":
        digests = {action["blob"] for row in rows for action in row["actions"] if action["type"] != "DELETE"}
        blob_root = data_root() / "projects" / project_id / "blobs"
        snapshots = {}
        for digest in sorted(digests):
            content = (blob_root / digest).read_bytes()
            if hashlib.sha256(content).hexdigest() != digest:
                raise GITronError("Stored snapshot failed integrity check")
            snapshots[digest] = base64.b64encode(content).decode("ascii")
        logs = [dict(row) for row in db.execute("SELECT * FROM execution_logs WHERE project_id=? ORDER BY id", (project_id,))]
        analysis_path = data_root() / "projects" / project_id / "analysis.json"
        analysis = json.loads(analysis_path.read_text()) if analysis_path.exists() else None
        return json.dumps({"provenance": "Reconstructed from an uploaded archive", "project": item,
                           "commits": rows, "execution_logs": logs,
                           "blobs_base64": snapshots, "analysis": analysis}, indent=2).encode(), "application/json", "json"
    if format == "csv":
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["Day", "Scheduled", "Phase", "Message", "Body", "Files", "Status", "SHA", "Pushed at"])
        for row in rows:
            writer.writerow([row["day"], row["scheduled_at"], row["phase"], row["message"], row["body"],
                             "; ".join(a["path"] for a in row["actions"]), row["status"], row["sha"], row["pushed_at"]])
        return stream.getvalue().encode("utf-8-sig"), "text/csv", "csv"
    if format in {"md", "pdf"}:
        origin = ("Verified from frozen source and a supplied plan or recorded checkpoints. No API calls or workflow PDF."
                  if item["analysis_stats"].get("planning_mode") in {"supplied-plan", "checkpoints"}
                  else "Generated from an uploaded archive and workflow PDF.")
        lines = [f"# {item['name']} — verified commit plan", "", origin, ""]
        for row in rows:
            lines += [f"## Day {row['day']}: {row['message']}",
                      f"Scheduled: {row['scheduled_at']} · Phase: {row['phase']} · Status: {row['status']}",
                      *( [f"Intent: {row['body']}"] if row['body'] else [] ),
                      f"SHA: {row['sha'] or '—'}", "Files: " + ", ".join(a["path"] for a in row["actions"]), ""]
        if format == "md":
            return "\n".join(lines).encode(), "text/markdown", "md"
        return simple_pdf(lines), "application/pdf", "pdf"
    raise GITronError("Unsupported export format")


def import_plan_json(data: bytes, source_path=None, **options) -> str:
    """Import a reviewed JSON plan as a new draft after validating and replaying it."""
    if len(data) > 750 * 1024 * 1024:
        raise GITronError("JSON plan is too large")
    try:
        document = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise GITronError("Invalid GITron JSON plan") from exc
    if isinstance(document, dict) and "blobs_base64" not in document:
        if source_path is None:
            raise GITronError("A supplied commit plan requires its project folder or ZIP")
        return verify_and_compile_plan(source_path, document, **options)
    try:
        source = document["project"]
        rows = document["commits"]
        encoded = document["blobs_base64"]
    except (TypeError, KeyError) as exc:
        raise GITronError("Invalid GITron JSON plan") from exc
    if not isinstance(source, dict) or not isinstance(rows, list) or not isinstance(encoded, dict) or not 1 <= len(rows) <= 1500:
        raise GITronError("Invalid GITron JSON structure")
    try:
        name = str(source["name"])[:120]
        start_date = str(source["start_date"])
        start = dt.date.fromisoformat(start_date)
        days = int(source["days"])
        timezone = str(source["timezone"])
        zone = ZoneInfo(timezone)
        branch = str(source["branch"])
        milestones = source["workflow"]
        working_days = tuple(int(day) for day in source.get("working_days", range(7)))
        rest_days = [int(day) for day in source.get("rest_days", [])]
        sections = source.get("workflow_sections", [])
        calendar_options = source.get("calendar_options", {})
        analysis_stats = source.get("analysis_stats", {})
    except (KeyError, ValueError, TypeError) as exc:
        raise GITronError("Invalid project metadata in JSON plan") from exc
    if not 1 <= days <= 365 or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch) or branch.startswith("-") or ".." in branch:
        raise GITronError("Invalid imported timeline or branch")
    if not isinstance(milestones, list) or not milestones or any(not isinstance(x, str) or not x for x in milestones):
        raise GITronError("Invalid imported workflow phases")
    if not working_days or len(set(working_days)) != len(working_days) or any(day not in range(7) for day in working_days):
        raise GITronError("Invalid imported working days")
    if (not isinstance(rest_days, list) or any(day not in range(1, days + 1) for day in rest_days)
            or not isinstance(sections, list) or not isinstance(calendar_options, dict)
            or not isinstance(analysis_stats, dict)):
        raise GITronError("Invalid imported analysis or calendar metadata")
    blobs: dict[str, bytes] = {}
    total = 0
    for digest, value in encoded.items():
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(value, str):
            raise GITronError("Invalid imported snapshot")
        try:
            content = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise GITronError("Invalid imported snapshot encoding") from exc
        total += len(content)
        if total > MAX_EXPANDED or hashlib.sha256(content).hexdigest() != digest:
            raise GITronError("Imported snapshot failed size or integrity check")
        blobs[digest] = content
    steps: list[tuple[str, list[dict], str]] = []
    schedule: list[tuple[int, str]] = []
    bodies: list[str] = []
    simulated: dict[str, bytes] = {}
    modes: set[str] = set()
    last_action: dict[str, str] = {}
    messages: set[str] = set()
    previous: dt.datetime | None = None
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("actions"), list) or not row["actions"]:
            raise GITronError("Invalid imported commit actions")
        phase, message = row.get("phase"), row.get("message")
        body = row.get("body", "")
        if phase not in milestones or not valid_commit_subject(message) or (message in messages and analysis_stats.get("planning_mode") not in {"supplied-plan", "checkpoints"}):
            raise GITronError("Invalid imported phase or commit message")
        messages.add(message)
        if not isinstance(body, str) or len(body) > 280 or "\x00" in body:
            raise GITronError("Invalid imported commit body")
        body = body.strip()
        try:
            scheduled = dt.datetime.fromisoformat(row["scheduled_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GITronError("Invalid imported scheduled time") from exc
        if scheduled.tzinfo is None or (previous and scheduled <= previous):
            raise GITronError("Imported timestamps must be timezone-aware and increasing")
        previous = scheduled
        local_date = scheduled.astimezone(zone).date()
        day = (local_date - start).days + 1
        if (day not in range(1, days + 1) or local_date.weekday() not in working_days or day in rest_days
                or not _inside_working_window(scheduled, timezone, calendar_options)):
            raise GITronError("Imported commit falls outside selected working days")
        actions: list[dict] = []
        for action in row["actions"]:
            if not isinstance(action, dict) or action.get("type") not in {"CREATE-FULL", "WRITE-PARTIAL", "MODIFY", "DELETE"}:
                raise GITronError("Invalid imported file action")
            if not isinstance(action.get("path"), str):
                raise GITronError("Invalid imported action path")
            parsed_path = _safe_member(action["path"])
            if _ignored(parsed_path):
                raise GITronError("Imported plan contains a filtered path")
            path = str(parsed_path)
            digest = action.get("blob")
            if action["type"] != "DELETE" and (not isinstance(digest, str) or digest not in blobs):
                raise GITronError("Imported action references a missing snapshot")
            clean = {"path": path, "type": action["type"], "blob": digest,
                     "executable": bool(action.get("executable", False))}
            actions.append(clean)
            last_action[path] = action["type"]
            if action["type"] == "DELETE":
                simulated.pop(path, None)
                modes.discard(path)
            else:
                _check_content_secrets(path, blobs[digest])
                simulated[path] = blobs[digest]
                if clean["executable"]:
                    modes.add(path)
                else:
                    modes.discard(path)
        steps.append((phase, actions, message))
        schedule.append((day, scheduled.isoformat()))
        bodies.append(body)
    if not simulated:
        raise GITronError("Imported plan has no final files")
    if any(last_action[path] != "CREATE-FULL" for path in simulated):
        raise GITronError("Every imported file must end with an exact CREATE-FULL snapshot")
    project_id = uuid.uuid4().hex
    root = data_root() / "projects" / project_id
    try:
        (root / "blobs").mkdir(parents=True, exist_ok=False)
        for digest, content in blobs.items():
            (root / "blobs" / digest).write_bytes(content)
        if analysis_stats.get("planning_mode") not in {"supplied-plan", "checkpoints"}:
            from .semantics import build_profiles
            validate_action_order(simulated, [actions for _, actions, _ in steps], build_profiles(simulated, modes))
        verify_git_replay(root, steps, simulated, modes)
        raw = root / "raw"
        raw.mkdir()
        for path, content in simulated.items():
            destination = raw.joinpath(*pathlib.PurePosixPath(path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o755 if path in modes else 0o644)
        analysis = document.get("analysis")
        if isinstance(analysis, dict):
            (root / "analysis.json").write_text(json.dumps(analysis, ensure_ascii=False))
        with connect() as db:
            db.execute("""INSERT INTO projects(id,name,remote,branch,start_date,timezone,days,working_days,status,
                          created_at,workflow,warnings,workflow_sections,rest_days,calendar_options,analysis_stats)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (project_id, name or "Imported plan", "", branch, start_date, timezone, days,
                        json.dumps(working_days), "DRAFT", now_iso(), json.dumps(milestones),
                        json.dumps(["Imported from JSON; set a remote and review before activation"]),
                        json.dumps(sections), json.dumps(rest_days), json.dumps(calendar_options),
                        json.dumps(analysis_stats)))
            for sequence, ((phase, actions, message), (day, scheduled), body) in enumerate(zip(steps, schedule, bodies)):
                db.execute("""INSERT INTO commits(project_id,sequence,day,scheduled_at,phase,message,body,actions)
                              VALUES (?,?,?,?,?,?,?,?)""",
                           (project_id, sequence, day, scheduled, phase, message, body, json.dumps(actions)))
        return project_id
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def simple_pdf(lines: list[str]) -> bytes:
    """Small portable text report; non-ASCII characters are transliterated."""
    def escaped(value: str) -> str:
        value = value.encode("latin-1", "replace").decode("latin-1")
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    wrapped = []
    for line in lines:
        while len(line) > 95:
            wrapped.append(line[:95])
            line = line[95:]
        wrapped.append(line)
    pages = [wrapped[i:i + 54] for i in range(0, len(wrapped), 54)] or [[]]
    objects: list[bytes] = []
    def add(data: bytes) -> int:
        objects.append(data)
        return len(objects)
    catalog = add(b"")
    pages_id = add(b"")
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []
    for page_lines in pages:
        stream = "BT /F1 9 Tf 48 798 Td 13 TL " + " ".join(f"({escaped(line)}) Tj T*" for line in page_lines) + " ET"
        payload = stream.encode("latin-1")
        content_id = add(f"<< /Length {len(payload)} >>\nstream\n".encode() + payload + b"\nendstream")
        page_ids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {font} 0 R >> >> /Contents {content_id} 0 R >>".encode()))
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{i} 0 R' for i in page_ids)}] /Count {len(page_ids)} >>".encode()
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)

# Public plan-driven API. Legacy PDF generation remains callable for old integrations.
def ingest_project_source(source_path, root):
    from .plan_engine import ingest_project_source as ingest
    return ingest(source_path, root)


def verify_and_compile_plan(source_path, plan=None, **options):
    from .plan_engine import verify_and_compile_plan as compile_plan
    return compile_plan(source_path, plan, **options)


def generate_agent_plan_prompt(source_path: str, schedule: dict | None = None) -> str:
    from .plan_engine import generate_agent_plan_prompt as generate
    return generate(source_path, schedule)


def record_checkpoint(source_path, message, phase='Development'):
    from .plan_engine import record_checkpoint as record
    return record(source_path, message, phase)
