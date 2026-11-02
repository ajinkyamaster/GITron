"""Cache GITron's grammar set while installation/build networking is available."""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from gitron.syntax import LANGUAGES


def main() -> None:
    options = argparse.ArgumentParser()
    options.add_argument("--strict", action="store_true")
    args = options.parse_args()
    try:
        from tree_sitter import Parser
        from tree_sitter_language_pack import downloaded_languages, get_language
    except ImportError as exc:
        raise SystemExit(f"Tree-sitter language pack is unavailable: {exc}") from exc
    failed = []
    for language in sorted(set(LANGUAGES.values())):
        try:
            parser = Parser(get_language(language))
            if parser.parse(b"").root_node is None or language not in downloaded_languages():
                failed.append(language)
        except Exception as exc:
            failed.append(f"{language} ({type(exc).__name__})")
    print(f"Cached {len(set(LANGUAGES.values())) - len(failed)} grammar parsers")
    if failed:
        print("Unavailable grammars: " + ", ".join(failed), file=sys.stderr)
        if args.strict:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
