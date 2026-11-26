from __future__ import annotations

import datetime as dt
import difflib
import email.parser
import email.policy
import html
import json
import pathlib
import secrets
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

from .core import GITronError, MAX_ARCHIVE, commits, connect, create_project, data_root, delete_project, export_plan, move_commit_day, project, set_project_state, set_remote, update_commit
from .worker import run_due, verify_remote


CSS = """
:root{--bg_canvas:#09090B;--bg_sidebar:#0C0C0F;--bg_surface:#111115;--bg_elevated:#17171C;--bg_selected:#1E1E25;--bg_input:#0D0D10;--border_subtle:#1F1F26;--border_focus:#383844;--text_primary:#ECECEF;--text_secondary:#9494A0;--text_muted:#565662;--cell_rest:#0D0D10;--cell_pending:#16161C;--cell_catchup:#24242D;--cell_pushed:#3A3A48;--diff_add_fg:#A8B5A2;--diff_del_fg:#B89696;--diff_hunk_fg:#6E6E7A;color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:var(--text_primary);background:var(--bg_canvas)}
*{box-sizing:border-box}::selection{background:var(--bg_selected);color:var(--text_primary)}body{margin:0}a{color:var(--text_primary);text-decoration:none}header{background:var(--bg_sidebar);border-bottom:1px solid var(--border_subtle);padding:20px 5vw;display:flex;justify-content:space-between;align-items:center}main{max-width:1200px;margin:36px auto;padding:0 28px}h1,h2,h3{font-weight:500;margin:0 0 16px}p{line-height:1.6}.muted,small{color:var(--text_secondary)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}.card{background:var(--bg_surface);border:1px solid var(--border_subtle);border-radius:8px;padding:24px;margin-bottom:20px}.setup{max-width:740px;margin:0 auto}label{display:block;color:var(--text_secondary);font-size:13px;margin:18px 0 6px}input,button,select{font:inherit}input,select{width:100%;background:var(--bg_input);color:var(--text_primary);border:1px solid var(--border_subtle);border-radius:5px;padding:11px;outline:none;accent-color:var(--text_secondary)}input:focus,select:focus{border-color:var(--border_focus)}input[type=file]{padding:8px}input::file-selector-button,button,.button{background:var(--bg_elevated);color:var(--text_primary);border:1px solid var(--border_subtle);border-radius:5px;padding:10px 15px;font-weight:500;cursor:pointer;text-decoration:none;display:inline-block}button:hover,.button:hover,button:focus-visible,input::file-selector-button:hover{background:var(--bg_selected);border-color:var(--border_focus);outline:none}button:disabled{color:var(--text_muted)}.inline{display:inline-block;margin-right:7px}.inline input{width:auto}.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.heatmap{display:grid;grid-template-columns:repeat(30,18px);gap:5px;overflow:auto;padding:10px 0}.day{width:18px;height:18px;border-radius:2px;background:var(--cell_pending);border:1px solid var(--border_subtle)}.day.pushed{background:var(--cell_pushed)}.day.catchup,.day.failed{background:var(--cell_catchup);border-color:var(--border_focus)}.day.failed:after{content:'!';color:var(--text_primary);font-size:12px}.day.rest{background:var(--cell_rest)}.badge{display:inline-block;border-radius:4px;padding:4px 9px;background:var(--bg_elevated);font-size:12px;color:var(--text_secondary)}.badge.PUSHED{color:var(--text_primary)}.timeline{display:grid;gap:9px}.commit{border:1px solid var(--border_subtle);padding:15px;border-radius:5px;background:var(--bg_surface)}.commit summary{cursor:pointer;font-weight:500}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:space-between}code,pre{font-family:ui-monospace,SFMono-Regular,monospace}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg_input);border:1px solid var(--border_subtle);border-radius:5px;padding:16px;max-height:500px;overflow:auto}.error,.warning{background:var(--bg_surface);border:1px solid var(--border_focus);padding:12px;border-radius:5px;margin:8px 0}footer{color:var(--text_muted);text-align:center;padding:30px}.diff-add{color:var(--diff_add_fg)}.diff-del{color:var(--diff_del_fg)}.diff-hunk{color:var(--diff_hunk_fg)}.diff-meta{color:var(--text_secondary)}
"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _diff(project_id: str, rows: list[dict], target: dict) -> str:
    state: dict[str, bytes] = {}
    root = data_root() / "projects" / project_id / "blobs"
    for row in rows:
        if row["id"] == target["id"]:
            chunks = []
            for action in row["actions"]:
                before = state.get(action["path"], b"")
                after = b"" if action["type"] == "DELETE" else (root / action["blob"]).read_bytes()
                try:
                    old = before.decode("utf-8").splitlines(keepends=True)
                    new = after.decode("utf-8").splitlines(keepends=True)
                except UnicodeDecodeError:
                    chunks.append(f"{action['path']}: binary asset ({len(before)} -> {len(after)} bytes)")
                    continue
                chunks.extend(difflib.unified_diff(old, new, fromfile="a/" + action["path"],
                                                    tofile="b/" + action["path"], n=3))
            return "".join(chunks)
        for action in row["actions"]:
            if action["type"] == "DELETE":
                state.pop(action["path"], None)
            else:
                state[action["path"]] = (root / action["blob"]).read_bytes()
    raise GITronError("Commit not found")


def page(title: str, content: str, refresh_seconds: int | None = None) -> bytes:
    refresh = f"<meta http-equiv='refresh' content='{refresh_seconds}'>" if refresh_seconds else ""
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)} · GITron</title>{refresh}<style>{CSS}</style></head><body><header><a href='/'><strong>GITron</strong></a>"
            f"<span class='muted'>Local archive replay planner</span></header><main>{content}</main>"
            f"<footer>Reconstructed plans and actual push times are recorded separately.</footer></body></html>").encode()


def diff_page(project_id: str, commit_id: int) -> bytes:
    with connect() as db:
        item = project(db, project_id)
        rows = commits(db, project_id)
    target = next((row for row in rows if row["id"] == commit_id), None)
    if target is None:
        raise GITronError("Commit not found")
    lines = []
    for line in _diff(project_id, rows, target).splitlines():
        style = ("diff-add" if line.startswith("+") and not line.startswith("+++") else
                 "diff-del" if line.startswith("-") and not line.startswith("---") else
                 "diff-hunk" if line.startswith("@@") else
                 "diff-meta" if line.startswith(("---", "+++")) else "")
        lines.append(f"<span class='{style}'>{esc(line)}</span>")
    content = f"<p><a href='/projects/{project_id}'>← {esc(item['name'])}</a></p><h1>{esc(target['message'])}</h1>"
    section = next((section for section in item["workflow_sections"] if section["title"] == target["phase"]), None)
    content += f"<p class='muted'>Day {target['day']} · {esc(target['phase'])} · {esc(target['status'])} · SHA {esc(target['sha'] or 'pending')}</p>"
    if section:
        content += f"<div class='card'><h3>Workflow context · PDF pages {esc(section['page_range'])}</h3><p>{esc(section['architectural_summary'])}</p><small>{esc(', '.join(section['technical_entities'][:12]))}</small></div>"
    content += "<pre>" + "\n".join(lines) + "</pre>"
    return page("Commit diff", content)


def form_token(token: str) -> str:
    return f"<input type='hidden' name='csrf' value='{esc(token)}'>"


def dashboard(token: str, *, new: bool = False) -> bytes:
    with connect() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM projects ORDER BY created_at DESC")]
    cards = "".join(f"<div class='card'><h3><a href='/projects/{esc(row['id'])}'>{esc(row['name'])}</a></h3>"
                    f"<p>{esc(row['status'])} · {row['days']} days · {esc(row['start_date'])}</p></div>" for row in rows)
    if not new:
        return page("Workspace", f"<div class='row'><h1>Workspace</h1><a class='button' href='/new'>New project</a></div><p class='muted'>Your verified timelines.</p><div class='grid'>{cards or '<p>No projects yet. Create a project to begin.</p>'}</div>")
    today = dt.date.today().isoformat()
    content = f"""<h1>Projects</h1><p class='muted'>Verify a supplied plan locally, then schedule its commits.</p>
    <div class='setup'><p><a href='/'>← Workspace</a></p><section class='card'><h2>New project</h2><form method='post' action='/projects' enctype='multipart/form-data'>
    {form_token(token)}<label>Project ZIP</label><input type='file' name='archive' accept='.zip' required>
    <label>Commit plan JSON (optional with recorded checkpoints)</label><input type='file' name='plan' accept='.json'>
    <label>Timezone</label><input name='timezone' value='Asia/Kolkata' required>
    <label>Remote</label><input name='remote'><label>Branch</label><input name='branch' value='main' required>
    <p>No API key or PDF required. Use the native app for local folders and Copy Agent Prompt.</p>
    <button>Verify &amp; create draft</button></form></section></div>"""
    return page("Projects", content)


def project_page(project_id: str, token: str) -> bytes:
    with connect() as db:
        item = project(db, project_id)
        rows = commits(db, project_id)
    pushed = sum(row["status"] == "PUSHED" for row in rows)
    today = dt.datetime.now(ZoneInfo(item["timezone"])).date()
    elapsed = max(0, min(item["days"], (today - dt.date.fromisoformat(item["start_date"])).days + 1))
    next_row = next((row for row in rows if row["status"] != "PUSHED"), None)
    next_text = f"Next: {next_row['scheduled_at']} · {next_row['message']}" if next_row else "All planned commits pushed"
    days = {i: "rest" if i in item["rest_days"] else "" for i in range(1, item["days"] + 1)}
    for row in rows:
        current = days[row["day"]]
        state = "catchup" if row.get("processing_state") == "CATCH_UP" or row["status"] == "PUSHED" and row.get("catchup") else "pushed" if row["status"] == "PUSHED" else "failed" if row["status"] == "FAILED" else "queued"
        order = {"": 0, "rest": 0, "pushed": 1, "catchup": 2, "queued": 3, "failed": 4}
        days[row["day"]] = state if order[state] >= order[current] else current
    heatmap = "".join(f"<a class='day {state}' title='Day {day}: {state or 'no commit'}' href='#day-{day}'></a>" for day, state in days.items())
    warnings = "".join(f"<div class='warning'>{esc(text)}</div>" for text in item["warnings"])
    remote_form = ""
    if item["status"] == "DRAFT":
        remote_form = f"<form method='post' action='/projects/{project_id}/remote'>{form_token(token)}<label>Remote URL</label>"
        remote_form += f"<input name='remote' value='{esc(item['remote'])}' placeholder='git@github.com:user/repo.git'>"
        remote_form += "<p><button class='secondary'>Save remote</button></p></form>"
    controls = ""
    if item["status"] == "DRAFT":
        controls = f"<form class='inline' method='post' action='/projects/{project_id}/state'>{form_token(token)}<input type='hidden' name='status' value='ACTIVE'><button>Activate</button></form>"
    elif item["status"] in {"ACTIVE", "PAUSED"}:
        new_state = "PAUSED" if item["status"] == "ACTIVE" else "ACTIVE"
        controls = f"<form class='inline' method='post' action='/projects/{project_id}/state'>{form_token(token)}<input type='hidden' name='status' value='{new_state}'><button class='secondary'>{'Pause' if new_state == 'PAUSED' else 'Resume'}</button></form>"
        if item["status"] == "ACTIVE":
            controls += f"<form class='inline' method='post' action='/projects/{project_id}/run'>{form_token(token)}<button>Push next now</button></form>"
    if item["remote"]:
        controls += f"<form class='inline' method='post' action='/projects/{project_id}/verify'>{form_token(token)}<button class='secondary'>Verify remote</button></form>"
    controls += (f"<form class='inline' method='post' action='/projects/{project_id}/delete'>"
                 f"{form_token(token)}<label><input type='checkbox' name='confirm' value='yes' required> "
                 "Delete local plan and stop future pushes</label><button class='danger'>Delete plan</button></form>")
    timeline = []
    for row in rows:
        display_status = "CATCH_UP" if row.get("processing_state") == "CATCH_UP" or \
                         row["status"] == "PUSHED" and row.get("catchup") else row["status"]
        actions = ", ".join(a["path"] for a in row["actions"])
        edit = ""
        if item["status"] == "DRAFT":
            edit = f"""<form method='post' action='/projects/{project_id}/commits/{row['id']}'>
            {form_token(token)}<label>Message</label><input name='message' value='{esc(row['message'])}' maxlength='100'>
            <label>Workflow phase</label><input name='phase' value='{esc(row['phase'])}' maxlength='120'>
            <label>Scheduled ISO time with offset</label><input name='scheduled_at' value='{esc(row['scheduled_at'])}'>
            <p><button class='secondary'>Save changes</button></p></form>"""
            edit += f"<form method='post' action='/projects/{project_id}/move/{row['id']}'>{form_token(token)}<label>Move to working day</label><input name='day' type='number' min='1' max='{item['days']}' value='{row['day']}'><p><button class='secondary'>Move</button></p></form>"
        sha = f"<code>{esc(row['sha'])}</code>" if row["sha"] else "—"
        link = ""
        if row["sha"] and item["remote"].startswith(("https://github.com/", "git@github.com:")):
            path = item["remote"].removeprefix("https://github.com/").removeprefix("git@github.com:").removesuffix(".git")
            link = f" <a target='_blank' rel='noopener noreferrer' href='https://github.com/{esc(path)}/commit/{esc(row['sha'])}'>GitHub commit</a>"
        timeline.append(f"""<details class='commit' id='day-{row['day']}'><summary>Day {row['day']} · {esc(row['message'])} <span class='badge {esc(display_status)}'>{esc(display_status)}</span></summary>
          <p class='muted'>{esc(row['scheduled_at'])} · {esc(row['phase'])}</p><p>Files: {esc(actions)}</p><p>SHA: {sha}{link}</p>
          {f'<p class="error">{esc(row["error"])}</p>' if row['error'] else ''}
          <p><a href='/projects/{project_id}/diff/{row['id']}' target='_blank'>View exact diff</a></p>{edit}</details>""")
    exports = " ".join(f"<a class='button secondary' href='/api/projects/{project_id}/export?format={format}'>{format.upper()}</a>" for format in ("md", "pdf", "json", "csv"))
    content = f"""<div class='row'><h1>{esc(item['name'])}</h1><span class='badge'>{esc(item['status'])}</span></div>
    <p class='muted'>{pushed}/{len(rows)} commits pushed · Day {elapsed} of {item['days']} · {esc(item['timezone'])}</p>
    <p>{esc(next_text)}</p>
    {warnings}<div class='card'><h2>Progress</h2><div class='heatmap'>{heatmap}</div>
    <small>Green: pushed · Amber: caught up · Blue: scheduled · Red: failed · Slate: rest day</small>
    <p class='muted'>{esc(item['analysis_stats'].get('files', 0))} files · {esc(item['analysis_stats'].get('parsed_files', 0))} sliced files · {esc(item['analysis_stats'].get('active_days', 0))} active days · {len(item['rest_days'])} rest days</p>
    <p class='toolbar'>{controls}</p></div>
    <div class='grid'><div class='card'><h2>Remote</h2><p><code>{esc(item['remote'] or 'No remote configured')}</code></p>{remote_form}</div>
    <div class='card'><h2>Export plan</h2><p class='muted'>Includes current status and verified SHAs.</p><div class='toolbar'>{exports}</div></div></div>
    <section class='card'><h2>Timeline</h2><div class='timeline'>{''.join(timeline)}</div></section>"""
    return page(item["name"], content, refresh_seconds=60 if item["status"] == "ACTIVE" else None)


class Handler(BaseHTTPRequestHandler):
    csrf = secrets.token_urlsafe(32)
    server_version = "GITron/0.1"

    def _send(self, body: bytes, content_type: str = "text/html; charset=utf-8", status: int = 200,
              filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, path: str) -> None:
        self.send_response(303)
        self.send_header("Location", path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _fields(self) -> dict[str, bytes]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_ARCHIVE + 26 * 1024 * 1024 or length < 0:
            raise GITronError("Upload exceeds ZIP and PDF size limits; use the desktop app for very large projects")
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        if content_type.startswith("multipart/form-data"):
            message = email.parser.BytesParser(policy=email.policy.default).parsebytes((f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
            if not message.is_multipart():
                raise GITronError("Malformed upload form")
            return {part.get_param("name", header="content-disposition"): part.get_payload(decode=True) or b""
                    for part in message.iter_parts()}
        return {key: value[0].encode() for key, value in urllib.parse.parse_qs(body.decode(), keep_blank_values=True).items()}

    def _check_csrf(self, fields: dict[str, bytes]) -> None:
        token = fields.get("csrf", b"").decode()
        if not secrets.compare_digest(token, self.csrf):
            raise GITronError("Invalid form token")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "").split(":")[0] in {"127.0.0.1", "localhost", "[::1]"}

    def do_GET(self) -> None:
        if not self._host_ok():
            self._send(b"Invalid host", "text/plain", 403)
            return
        path = urllib.parse.urlsplit(self.path)
        parts = path.path.strip("/").split("/")
        try:
            if path.path == "/":
                self._send(dashboard(self.csrf))
            elif path.path == "/new":
                self._send(dashboard(self.csrf, new=True))
            elif len(parts) == 4 and parts[0] == "projects" and parts[2] == "diff":
                self._send(diff_page(parts[1], int(parts[3])))
            elif len(parts) == 2 and parts[0] == "projects":
                self._send(project_page(parts[1], self.csrf))
            elif len(parts) == 2 and parts == ["api", "projects"]:
                with connect() as db:
                    data = [dict(row) for row in db.execute("SELECT id,name,status,start_date,days FROM projects ORDER BY created_at DESC")]
                self._send(json.dumps(data).encode(), "application/json")
            elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "commits":
                with connect() as db:
                    self._send(json.dumps(commits(db, parts[2])).encode(), "application/json")
            elif len(parts) == 4 and parts[:2] == ["api", "projects"] and parts[3] == "export":
                format = urllib.parse.parse_qs(path.query).get("format", ["json"])[0]
                with connect() as db:
                    body, mime, extension = export_plan(db, parts[2], format)
                self._send(body, mime, filename=f"gitron-plan-{parts[2][:8]}.{extension}")
            elif len(parts) == 5 and parts[:2] == ["api", "projects"] and parts[3] == "diff":
                with connect() as db:
                    rows = commits(db, parts[2])
                target = next((r for r in rows if r["id"] == int(parts[4])), None)
                if target is None:
                    raise GITronError("Commit not found")
                self._send(_diff(parts[2], rows, target).encode(), "text/plain; charset=utf-8")
            elif len(parts) == 3 and parts[:2] == ["api", "projects"]:
                with connect() as db:
                    self._send(json.dumps(project(db, parts[2])).encode(), "application/json")
            else:
                self._send(b"Not found", "text/plain", 404)
        except (GITronError, ValueError) as exc:
            self._send(page("Error", f"<div class='error'>{esc(exc)}</div>"), status=400)

    def do_POST(self) -> None:
        if not self._host_ok():
            self._send(b"Invalid host", "text/plain", 403)
            return
        parts = urllib.parse.urlsplit(self.path).path.strip("/").split("/")
        try:
            fields = self._fields()
            self._check_csrf(fields)
            get = lambda key: fields.get(key, b"").decode("utf-8")
            if parts == ["projects"]:
                from .core import verify_and_compile_plan
                import tempfile
                with tempfile.TemporaryDirectory(prefix="gitron-upload-") as temp:
                    source = pathlib.Path(temp) / "project.zip"
                    source.write_bytes(fields["archive"])
                    pid = verify_and_compile_plan(source, fields.get("plan") or None,
                                                  timezone=get("timezone") or "Asia/Kolkata",
                                                  remote=get("remote"), branch=get("branch") or "main")
                self._redirect(f"/projects/{pid}")
            elif len(parts) >= 3 and parts[0] == "projects":
                pid = parts[1]
                if parts[2:] == ["delete"]:
                    if get("confirm") != "yes":
                        raise GITronError("Confirm deletion of the local plan")
                    delete_project(pid)
                    self._redirect("/")
                    return
                if parts[2:] == ["verify"]:
                    result = verify_remote(pid)
                    label = ("Remote matches GITron's recorded head" if result["matches"] else
                             "Remote does not match GITron's recorded head")
                    content = (f"<h1>{esc(label)}</h1><p>Remote: {esc(result['remote_sha'] or 'empty')}</p>"
                               f"<p>Expected remote head: {esc(result['expected_remote_sha'] or 'empty')}</p>"
                               f"<p>Last GITron commit: {esc(result['last_pushed_sha'] or 'none')}</p>"
                               f"<p>{result['pushed_commits']}/{result['total_commits']} commits pushed.</p>"
                               f"<p><a href='/projects/{pid}'>Back to plan</a></p>")
                    self._send(page("Remote verification", content))
                    return
                if parts[2:] == ["state"] and get("status") == "ACTIVE":
                    from .__main__ import activate_project
                    activate_project(pid)
                    self._redirect(f"/projects/{pid}")
                    return
                with connect() as db:
                    if parts[2:] == ["remote"]:
                        set_remote(db, pid, get("remote"))
                    elif parts[2:] == ["state"]:
                        set_project_state(db, pid, get("status"))
                    elif len(parts) == 4 and parts[2] == "commits":
                        update_commit(db, pid, int(parts[3]), message=get("message"), scheduled_at=get("scheduled_at"),
                                      phase=get("phase"))
                    elif len(parts) == 4 and parts[2] == "move":
                        move_commit_day(db, pid, int(parts[3]), int(get("day")))
                    elif parts[2:] == ["run"]:
                        if project(db, pid)["status"] != "ACTIVE":
                            raise GITronError("Schedule is not active")
                    else:
                        raise GITronError("Unknown operation")
                if parts[2:] == ["run"]:
                    run_due(pid, force_next=True)
                self._redirect(f"/projects/{pid}")
            else:
                raise GITronError("Unknown operation")
        except (GITronError, ValueError, KeyError, UnicodeDecodeError, OSError, subprocess.CalledProcessError) as exc:
            self._send(page("Error", f"<div class='error'>{esc(exc)}</div><p><a href='/'>Back to projects</a></p>"), status=400)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in {"127.0.0.1", "::1"}:
        raise GITronError("The dashboard must bind to loopback")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"GITron dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
