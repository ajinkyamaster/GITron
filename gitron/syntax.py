"""Optional Tree-sitter analysis; Python's stdlib AST remains authoritative for Python."""

from __future__ import annotations

import functools
import pathlib
import re
import sys

MAX_AST_BYTES = 2_000_000

LANGUAGES = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
             ".tsx": "tsx", ".go": "go", ".rs": "rust", ".java": "java", ".c": "c",
             ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
             ".rb": "ruby", ".php": "php", ".sql": "sql", ".html": "html",
             ".htm": "html", ".css": "css"}


@functools.lru_cache(maxsize=1)
def _configure_pack() -> None:
    if getattr(sys, "frozen", False):
        from tree_sitter_language_pack import configure
        bundle = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(sys.executable).parent))
        configure({"cache_dir": str(bundle / "parser-cache")})


@functools.lru_cache(maxsize=24)
def _parser(extension: str):
    try:
        from tree_sitter import Language, Parser
        try:
            from tree_sitter_language_pack import downloaded_languages, get_language
            _configure_pack()
            language_name = LANGUAGES.get(extension)
            if language_name and language_name in downloaded_languages():
                return Parser(get_language(language_name))
        except Exception:
            pass
        if extension in {".js", ".jsx"}:
            import tree_sitter_javascript as grammar
            language = Language(grammar.language())
        elif extension in {".ts", ".tsx"}:
            import tree_sitter_typescript as grammar
            language = Language(grammar.language_tsx() if extension == ".tsx" else grammar.language_typescript())
        else:
            return None
        return Parser(language)
    except (ImportError, AttributeError, KeyError, TypeError):
        return None


def _extension(name: str) -> str:
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def parse_tree(name: str, content: bytes):
    if len(content) > MAX_AST_BYTES:
        return None
    parser = _parser(_extension(name))
    return parser.parse(content) if parser else None


_IMPORT_PATTERNS = (
    re.compile(r"\bfrom\s*['\"]([^'\"]+)['\"]", re.S),
    re.compile(r"\bimport\s*(?:\(\s*)?['\"]([^'\"]+)['\"]", re.S),
    re.compile(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]", re.S),
)


def script_specifiers(name: str, content: bytes) -> set[str]:
    try:
        source = content[:MAX_AST_BYTES].decode("utf-8")
    except UnicodeDecodeError:
        return set()
    tree = parse_tree(name, content)
    fragments: list[str] = []
    if tree and not tree.root_node.has_error:
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in {"import_statement", "export_statement", "call_expression"}:
                fragments.append(content[node.start_byte:node.end_byte].decode("utf-8"))
            elif node.type not in {"comment", "string", "template_string"}:
                stack.extend(reversed(node.named_children))
    else:
        fragments = [source]
    return {match.group(1) for fragment in fragments for pattern in _IMPORT_PATTERNS
            for match in pattern.finditer(fragment)}


def script_snapshots(name: str, content: bytes, minimum_lines: int = 80) -> list[bytes]:
    """Return up to three parser-verified top-level prefixes for supported languages."""
    if content.count(b"\n") < minimum_lines:
        return []
    tree = parse_tree(name, content)
    if tree is None or tree.root_node.has_error:
        return []
    nodes = [node for node in tree.root_node.named_children if node.type not in {"comment", "hash_bang_line"}]
    if len(nodes) < 6:
        return []
    snapshots: list[bytes] = []
    indices = ({len(nodes) // 4, len(nodes) // 2, 3 * len(nodes) // 4}
               if len(nodes) >= 9 else {len(nodes) // 3, 2 * len(nodes) // 3})
    for index in sorted(indices):
        partial = content[:nodes[index - 1].end_byte]
        later_names = []
        for node in nodes[index:]:
            candidate = next((child for child in node.named_children if child.type in
                              {"function_declaration", "function_definition", "function_item",
                               "class_declaration", "class_definition", "interface_declaration",
                               "lexical_declaration", "variable_declaration", "type_declaration",
                               "struct_item", "struct_specifier", "trait_item", "enum_declaration"}), node)
            named = candidate.child_by_field_name("name")
            if named is None and candidate.type in {"lexical_declaration", "variable_declaration"}:
                declarator = next((child for child in candidate.named_children
                                   if child.type == "variable_declarator"), None)
                named = declarator.child_by_field_name("name") if declarator else None
            if named:
                later_names.append(content[named.start_byte:named.end_byte])
        if any(re.search(rb"\b" + re.escape(symbol_name) + rb"\b", partial)
               for symbol_name in later_names):
            continue
        partial_tree = parse_tree(name, partial)
        if partial and partial != content and partial_tree and not partial_tree.root_node.has_error:
            snapshots.append(partial)
    return snapshots
