"""Bounded local code fingerprints, PDF alignment, and source-derived narratives."""

from __future__ import annotations

import ast
import collections
import math
import pathlib
import re

from .syntax import LANGUAGES, MAX_AST_BYTES, parse_tree, script_specifiers


def _words(value: str) -> list[str]:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", value)]


def _sentence(value: str) -> str:
    return re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", value.strip()))[0][:180]


def stratum(path: str) -> int:
    lower = path.lower()
    leaf = pathlib.PurePosixPath(lower).name
    if leaf in {"package.json", "package-lock.json", "pyproject.toml", "requirements.txt",
                "go.mod", "cargo.toml", "pom.xml", "makefile", "dockerfile", "docker-compose.yml",
                ".gitignore", ".env.example", ".env.sample", ".env.template", "tsconfig.json",
                "__init__.py"} or \
            lower.endswith((".sql", ".yaml", ".yml", ".toml")):
        return 0
    if "test" in lower or "spec" in lower or leaf.startswith("readme") or "/docs/" in f"/{lower}/":
        return 3
    if any(token in lower for token in ("model", "schema", "database", "db/", "util", "auth", "core/", "lib/")):
        return 1
    return 2


def _python_declarations(content: bytes, path: str) -> tuple[str, list[dict], list[str], bool]:
    try:
        source = content.decode("utf-8")
        tree = ast.parse(source, filename=path)
    except (UnicodeDecodeError, SyntaxError):
        return "", [], [], False
    offsets = [0]
    for line in content.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    module_doc = _sentence(ast.get_docstring(tree) or "")
    if not module_doc:
        module_doc = _sentence(" ".join(line.lstrip("# ") for line in source.splitlines()[:12]
                                        if line.lstrip().startswith("#")))
    names = {node.name for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))}
    declarations = []
    def collect(node, parent=""):
        if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        name = f"{parent}.{node.name}" if parent else node.name
        decorators = [ast.unparse(decorator)[:150] for decorator in getattr(node, "decorator_list", [])]
        kind = "class" if isinstance(node, ast.ClassDef) else "function"
        if node.name.startswith("test_"):
            kind = "test"
        elif any(re.search(r"\b(route|get|post|put|delete|patch)\b", value, re.I) for value in decorators):
            kind = "route"
        elif kind == "class" and any(re.search(r"\b(Model|BaseModel|Schema|Entity)\b", ast.unparse(base)) for base in node.bases):
            kind = "model"
        if isinstance(node, ast.ClassDef):
            signature = f"class {node.name}({', '.join(ast.unparse(base) for base in node.bases)})"
        else:
            signature = ("async " if isinstance(node, ast.AsyncFunctionDef) else "") + \
                f"def {node.name}({ast.unparse(node.args)})" + \
                (f" -> {ast.unparse(node.returns)}" if node.returns else "")
        references = sorted({child.id for child in ast.walk(node) if isinstance(child, ast.Name)
                             and isinstance(child.ctx, ast.Load) and child.id in names and child.id != node.name})
        declarations.append({"name": name, "kind": kind, "start_byte": offsets[node.lineno - 1],
                             "end_byte": offsets[node.end_lineno] if node.end_lineno else len(content),
                             "start_line": node.lineno, "end_line": node.end_lineno or node.lineno,
                             "signature": signature[:220], "decorators_or_routes": decorators[:10],
                             "docstring_summary": _sentence(ast.get_docstring(node) or ""),
                             "referenced_symbols": references[:30]})
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    collect(child, node.name)
    for node in tree.body:
        collect(node)
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * node.level + (node.module or ""))
    return module_doc, declarations[:150], sorted(set(imports))[:100], True


_KINDS = {"function_definition": "function", "function_declaration": "function",
          "method_declaration": "function", "method_definition": "function",
          "class_definition": "class", "class_declaration": "class", "struct_item": "class",
          "struct_specifier": "class", "interface_declaration": "interface",
          "trait_item": "interface", "function_item": "function", "method_declaration": "function",
          "type_declaration": "class", "type_specification": "class", "impl_item": "class",
          "module": "class", "element": "interface"}


def _other_declarations(path: str, content: bytes) -> tuple[str, list[dict], list[str], bool]:
    source = content.decode("utf-8", "replace")
    header = []
    for line in source.splitlines()[:12]:
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*", "--")):
            header.append(stripped.lstrip("#/*- "))
        elif stripped:
            break
    tree = parse_tree(path, content)
    declarations = []
    if tree and not tree.root_node.has_error:
        queue = [(node, 0) for node in tree.root_node.named_children]
        while queue and len(declarations) < 150:
            node, depth = queue.pop(0)
            candidate = node
            if node.type in {"export_statement", "decorated_definition", "public_field_definition"}:
                queue[:0] = [(child, depth) for child in node.named_children]
                continue
            if node.type in _KINDS or node.type in {"lexical_declaration", "variable_declaration",
                                                   "type_alias_declaration", "enum_declaration"}:
                named = node.child_by_field_name("name")
                if named is None and node.type in {"lexical_declaration", "variable_declaration"}:
                    declarator = next((child for child in node.named_children
                                       if child.type == "variable_declarator"), None)
                    named = declarator.child_by_field_name("name") if declarator else None
                if named is None:
                    named = next((child for child in node.named_children if child.type in
                                  {"identifier", "type_identifier", "field_identifier", "name"}), None)
                name = content[named.start_byte:named.end_byte].decode("utf-8", "replace") if named else ""
                if name:
                    raw = content[node.start_byte:min(node.end_byte, node.start_byte + 350)].decode("utf-8", "replace")
                    signature = raw.split("{", 1)[0].split("\n", 1)[0].strip()[:220]
                    declarations.append({"name": name, "kind": _KINDS.get(node.type, "interface"),
                                         "start_byte": node.start_byte, "end_byte": node.end_byte,
                                         "start_line": node.start_point.row + 1, "end_line": node.end_point.row + 1,
                                         "signature": signature, "decorators_or_routes": re.findall(
                                             r"@[A-Za-z_.]+(?:\([^)]{0,100}\))?", raw)[:10],
                                         "docstring_summary": "", "referenced_symbols": []})
                if depth < 1 and node.type in {"class_declaration", "class_definition", "impl_item"}:
                    queue[:0] = [(child, depth + 1) for child in node.named_children]
            elif depth < 2 and node.type in {"declaration_list", "class_body", "program", "source_file"}:
                queue[:0] = [(child, depth + 1) for child in node.named_children]
    if not declarations:
        pattern = re.compile(r"(?m)^\s*(?:export\s+|pub\s+|public\s+|static\s+|async\s+)*"
                             r"(class|interface|struct|trait|func|fn|function|def|CREATE\s+TABLE)\s+"
                             r"([A-Za-z_][\w]*)", re.I)
        for match in list(pattern.finditer(source))[:100]:
            prefix = source[:match.start()].encode()
            name = match.group(2)
            declarations.append({"name": name, "kind": "class" if match.group(1).lower() in
                                 {"class", "struct", "trait", "interface", "create table"} else "function",
                                 "start_byte": len(prefix), "end_byte": len(source[:match.end()].encode()),
                                 "start_line": source.count("\n", 0, match.start()) + 1,
                                 "end_line": source.count("\n", 0, match.end()) + 1,
                                 "signature": match.group().strip(), "decorators_or_routes": [],
                                 "docstring_summary": "", "referenced_symbols": []})
    names = {entry["name"] for entry in declarations}
    for entry in declarations:
        fragment = content[entry["start_byte"]:entry["end_byte"]].decode("utf-8", "replace")
        entry["referenced_symbols"] = sorted({name for name in names if name != entry["name"] and
                                              re.search(rf"\b{re.escape(name)}\b", fragment)})[:30]
        if entry["kind"] == "function" and entry["name"].startswith(("test_", "Test")):
            entry["kind"] = "test"
        if any(re.search(r"\b(route|get|post|put|delete|patch)\b", route, re.I)
               for route in entry["decorators_or_routes"]):
            entry["kind"] = "route"
    imports = list(script_specifiers(path, content)) if path.endswith((".js", ".jsx", ".ts", ".tsx")) else []
    imports += re.findall(r"(?m)^\s*(?:import|use|require|#include|from)\s+[\"<]?([A-Za-z_][\w./:-]*)", source)
    if path.endswith(".go"):
        imports += re.findall(r"(?ms)^\s*import\s*\((.*?)\)", source)
        imports = [match for item in imports for match in
                   (re.findall(r'"([^"\n]+)"', item) if "\n" in item else [item])]
    if path.endswith(".rs"):
        imports += re.findall(r"(?m)^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;", source)
    return _sentence(" ".join(header)), declarations, sorted(set(imports))[:100], bool(tree and not tree.root_node.has_error)


def profile_file(path: str, content: bytes, files: dict[str, bytes], executable: set[str],
                 suffix_index: dict[str, set[str]] | None = None,
                 go_directories: dict[str, set[str]] | None = None) -> dict:
    language = LANGUAGES.get(pathlib.PurePosixPath(path).suffix.lower(), "config" if
                             pathlib.PurePosixPath(path).suffix.lower() in {".json", ".yaml", ".yml", ".toml"} else "asset")
    bounded = len(content) > MAX_AST_BYTES
    analyzed = content[:MAX_AST_BYTES] if bounded else content
    if language == "python" and not bounded:
        doc, declarations, imports, parsed = _python_declarations(content, path)
    else:
        doc, declarations, imports, parsed = _other_declarations(path, analyzed) if language != "asset" else ("", [], [], False)
    from .core import _python_dependencies, _script_dependencies
    names = set(files)
    internal = (_python_dependencies(path, content, names) if language == "python" else
                _script_dependencies(path, content, names, files) if language in {"javascript", "typescript", "tsx"} else set())
    if language not in {"python", "javascript", "typescript", "tsx"}:
        for imported in imports:
            raw = imported.strip('"<>')
            stem = raw.replace("::", "/").replace("crate/", "").replace(".", "/")
            relatives = (raw, stem, f"{stem}.go", f"{stem}.rs", f"{stem}.java", f"{stem}.h",
                         f"{stem}/mod.rs", str(pathlib.PurePosixPath(path).parent / raw))
            if suffix_index is None:
                matches = {candidate for candidate in names if candidate in relatives or
                           any(candidate.endswith("/" + relative) for relative in relatives)}
            else:
                matches = set().union(*(suffix_index.get(relative, set()) for relative in relatives))
            if language == "go":
                matches.update((go_directories or {}).get(raw.rsplit("/", 1)[-1], set()))
            internal.update(matches - {path})
    external = sorted({item.split(".")[0].split("/")[0] for item in imports if item and
                       not item.startswith(".") and not any(item in dep or item.replace(".", "/") in dep for dep in internal)})[:100]
    source = analyzed.decode("utf-8", "replace") if language != "asset" else ""
    if language == "python" and parsed:
        tree = ast.parse(source, filename=path)
        literals = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                    and isinstance(node.value, str)] if tree else []
    else:
        literals = re.findall(r"['\"]([^'\"\n]{4,100})['\"]", source)[:100]
    strings = list(dict.fromkeys(value[:100] for value in literals
                                 if len(value) <= 100 and ("/" in value or "_" in value or " " in value)))[:40]
    route_paths = list(dict.fromkeys(re.findall(r"/[A-Za-z][\w/{}/:-]{2,80}", source)))[:40]
    return {"path": path, "language": language, "size_bytes": len(content),
            "line_count": content.count(b"\n") + bool(content and not content.endswith(b"\n")),
            "is_executable": path in executable, "stratum": stratum(path), "module_docstring": doc,
            "declarations": declarations, "internal_dependencies": sorted(internal),
            "external_dependencies": external, "string_literals": strings,
            "route_paths": route_paths, "paired_source_or_test": [],
            "parser_verified": parsed, "analysis_bounded": bounded}


def build_profiles(files: dict[str, bytes], executable: set[str]) -> dict[str, dict]:
    suffix_index: dict[str, set[str]] = collections.defaultdict(set)
    go_directories: dict[str, set[str]] = collections.defaultdict(set)
    for path in files:
        parts = pathlib.PurePosixPath(path).parts
        for index in range(len(parts)):
            suffix_index["/".join(parts[index:])].add(path)
        if path.endswith(".go"):
            go_directories[pathlib.PurePosixPath(path).parent.name].add(path)
    profiles = {path: profile_file(path, content, files, executable, suffix_index, go_directories)
                for path, content in files.items()}
    for path, profile in profiles.items():
        if profile["stratum"] != 3 or "test" not in path.lower() and "spec" not in path.lower():
            continue
        stem = pathlib.PurePosixPath(path).stem
        stem = re.sub(r"^(test_|spec_)|(_test|\.test|\.spec)$", "", stem)
        paired = set(profile["internal_dependencies"])
        paired.update(candidate for candidate in profiles if candidate != path and
                      pathlib.PurePosixPath(candidate).stem == stem)
        profile["paired_source_or_test"] = sorted(paired)[:30]
    return profiles


def align_profiles(profiles: dict[str, dict], sections: list[dict], groups: list[list[str]]) -> dict[str, str]:
    """Direct entities plus TF-IDF cosine, with monotone dependency order."""
    section_terms = [collections.Counter(_words(section["title"] + " " + section["body_text"])) for section in sections]
    documents = section_terms + [collections.Counter(_words(profile["path"] + " " +
                 profile["module_docstring"] + " " + " ".join(item["name"] + " " + item["docstring_summary"]
                 for item in profile["declarations"]) + " " + " ".join(profile["string_literals"])))
                 for profile in profiles.values()]
    df = collections.Counter(term for document in documents for term in document)
    total = len(documents)
    def vector(counter):
        return {term: (1 + math.log(count)) * math.log((total + 1) / (df[term] + 1))
                for term, count in counter.items() if count}
    vectors = [vector(value) for value in section_terms]
    mapping = {}
    last = 0
    group_count = len(groups)
    verification_phase = bool(re.search(r"test|verif|quality|documentation", sections[-1]["title"], re.I))
    for group_index, group in enumerate(groups):
        scores = []
        for index, section in enumerate(sections):
            score = 0.0
            for path in group:
                profile = profiles[path]
                text = (profile["path"] + " " + profile["module_docstring"] + " " + " ".join(
                    entry["name"] + " " + entry["signature"] + " " + entry["docstring_summary"] + " " +
                    " ".join(entry["decorators_or_routes"]) for entry in profile["declarations"]) + " " +
                    " ".join(profile["string_literals"] + profile["route_paths"]))
                candidate = vector(collections.Counter(_words(text)))
                dot = sum(value * vectors[index].get(term, 0) for term, value in candidate.items())
                magnitude = math.sqrt(sum(value * value for value in candidate.values()) *
                                      sum(value * value for value in vectors[index].values()))
                score += dot / magnitude if magnitude else 0
                score += 1.5 * sum(entity.casefold() in text.casefold() for entity in section["technical_entities"])
                if profile["stratum"] == 0 and index == 0:
                    score += 5
                if profile["stratum"] == 3 and index == len(sections) - 1:
                    score += 5
            scores.append(score)
        fallback = min(len(sections) - 1, group_index * len(sections) // max(group_count, 1))
        if all(profiles[path]["stratum"] == 0 for path in group) and last == 0:
            eligible = [0]
        elif all(profiles[path]["stratum"] == 3 for path in group):
            eligible = [len(sections) - 1]
        else:
            stop = len(sections) - int(verification_phase and len(sections) > 1)
            eligible = list(range(last, max(last + 1, stop)))
        choice = max(eligible, key=lambda index: (scores[index], -abs(index - fallback), -index))
        if max(scores[index] for index in eligible) < 0.05:
            choice = min(eligible, key=lambda index: (abs(index - fallback), index))
        last = choice
        for path in group:
            mapping[path] = sections[choice]["phase_id"]
    return mapping


def offline_message(path: str, action: str, snapshot: bytes, previous: bytes,
                    profile: dict, used: set[str], section: dict | None = None) -> str:
    leaf = pathlib.PurePosixPath(path).stem.replace("-", "_")
    scope = re.sub(r"[^a-z0-9-]", "-", leaf.lower().replace("_", "-"))[:25].strip("-") or "project"
    if profile["stratum"] == 3 and scope.startswith("test-"):
        scope = scope.removeprefix("test-") or "tests"
    if scope in {"index", "main", "init", "app", "test"} and len(pathlib.PurePosixPath(path).parts) > 1:
        scope = re.sub(r"[^a-z0-9-]", "-", pathlib.PurePosixPath(path).parent.name.lower())[:25] or scope
    after = snapshot.decode("utf-8", "replace")
    added = [entry for entry in profile["declarations"]
             if len(previous) <= entry["start_byte"] < entry["end_byte"] <= len(snapshot)]
    selected = added[0] if added else next((entry for entry in profile["declarations"]
                                            if entry["end_byte"] <= len(snapshot)), None)
    symbol = selected["name"].split(".")[-1] if selected else leaf
    symbol = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", symbol).replace("_", " ").replace("-", " ").strip().lower()
    phase_terms = [word for word in _words(section["title"] if section else "")
                   if word not in {"project", "setup", "core", "implementation", "integration",
                                   "tests", "test", "verification", "documentation", "and"}]
    phase_hint = " ".join(phase_terms[:2])
    if scope in {"code", "file", "module", "project", "group", "app"}:
        scope = next((term[:25] for term in phase_terms if len(term) > 3),
                     "routes" if profile["route_paths"] else "runtime")
    if selected:
        decorators = " ".join(selected["decorators_or_routes"])
        route = re.search(r"/[A-Za-z][\w/{}/:-]{1,60}", decorators)
        if selected["kind"] == "route" and route:
            symbol += f" route {route.group()}"
        elif selected["kind"] == "model" and "model" not in symbol:
            symbol += " model"
        elif re.search(r"\b(?:click|typer|command)\b", decorators, re.I) and "command" not in symbol:
            symbol += " command"
        if symbol in {"run", "main", "handle", "process", "execute"} and selected["docstring_summary"]:
            words = re.findall(r"[A-Za-z0-9/-]+", selected["docstring_summary"])
            symbol = " ".join(words[:7]).lower() or symbol
    if leaf == "__init__" and profile["module_docstring"]:
        symbol = re.sub(r"[^a-z0-9 ]", "", profile["module_docstring"].lower()).strip()[:35]
    elif profile["language"] == "asset" and path.endswith(".sh"):
        command = re.search(r"(?m)^\s*python\d?\s+-m\s+([A-Za-z_.]+)", after)
        symbol = (command.group(1).replace(".", " ").replace("_", " ") + " launcher") if command else symbol + " launcher"
    elif symbol == "readme":
        heading = re.search(r"(?m)^#\s+(.{3,60})", after)
        symbol = (heading.group(1).strip().lower() if heading else phase_hint or "project") + " workflow"
    elif symbol in {"main", "index", "run"} and phase_hint:
        symbol = phase_hint + (" workflow" if symbol == "readme" else " entry point" if symbol == "main" else "")
    if pathlib.PurePosixPath(path).name == "__init__.py":
        message = f"build({scope}): establish {symbol}"
    elif profile["stratum"] == 3 and "test" in path.lower():
        message = f"test({scope}): cover {symbol} behavior"
    elif path.lower().endswith((".md", ".rst")):
        message = f"docs({scope}): document {symbol if symbol.endswith('workflow') else symbol + ' workflow'}"
    elif profile["stratum"] == 0:
        verb = "scaffold" if action == "WRITE-PARTIAL" else "complete" if previous else "define"
        message = f"build({scope}): {verb} {symbol} configuration"
    else:
        verb = {"WRITE-PARTIAL": "scaffold", "MODIFY": "implement", "CREATE-FULL": "implement"}.get(action, "add")
        if previous and action == "CREATE-FULL":
            verb = "complete"
        message = f"feat({scope}): {verb} {symbol}"
    message = message[:72].rstrip()
    if message in used:
        for alternative in (f"{message[:55]} in {pathlib.PurePosixPath(path).name}",
                            f"{message[:55]} for {profile['language']}",
                            f"{message[:60]} phase {len(used) + 1}"):
            if alternative[:72] not in used:
                message = alternative[:72]
                break
    used.add(message)
    return message
