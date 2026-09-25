from __future__ import annotations

import argparse
import html
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\n]+)\)")
HTML_LINK_RE = re.compile(r"<(?:a|img)\b[^>]*(?:href|src)=[\"']([^\"']+)[\"']", re.IGNORECASE)
HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
HTML_ANCHOR_RE = re.compile(r"<(?:a|[^>]+\s)\b(?:id|name)=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _strip_fenced_code(text: str) -> str:
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        marker = None
        if stripped.startswith("```"):
            marker = "```"
        elif stripped.startswith("~~~"):
            marker = "~~~"
        if marker:
            if fence is None:
                fence = marker
                lines.append("\n")
                continue
            if fence == marker:
                fence = None
                lines.append("\n")
                continue
        lines.append("\n" if fence else line)
    return "".join(lines)


def _destination(raw: str) -> str:
    raw = html.unescape(raw.strip())
    if raw.startswith("<") and ">" in raw:
        return raw[1 : raw.index(">")].strip()
    return raw.split(maxsplit=1)[0] if raw else ""


def _iter_links(text: str):
    text = _strip_fenced_code(text)
    matches = list(MARKDOWN_LINK_RE.finditer(text)) + list(HTML_LINK_RE.finditer(text))
    for match in sorted(matches, key=lambda item: item.start()):
        dest = _destination(match.group(1))
        if not dest:
            continue
        line = text.count("\n", 0, match.start()) + 1
        yield line, dest


def _heading_slug(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", value)
    value = value.replace("`", "")
    chars: list[str] = []
    for char in value.casefold().strip():
        if char.isspace():
            chars.append("-")
        elif char in "-_":
            chars.append(char)
        elif unicodedata.category(char)[0] in {"L", "N"}:
            chars.append(char)
    return re.sub(r"-+", "-", "".join(chars)).strip("-")


def _anchors(path: Path) -> set[str]:
    text = _strip_fenced_code(path.read_text(encoding="utf-8"))
    anchors: set[str] = set(HTML_ANCHOR_RE.findall(text))
    seen: dict[str, int] = {}
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if not match:
            continue
        base = _heading_slug(match.group(2))
        if not base:
            continue
        count = seen.get(base, 0)
        seen[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def _relative_display(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def check_markdown_links(root: Path, markdown_files: list[Path]) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}

    for source in markdown_files:
        source = source.resolve()
        text = source.read_text(encoding="utf-8")
        for line, destination in _iter_links(text):
            if destination.startswith("//"):
                continue
            parsed = urlsplit(destination)
            if parsed.scheme:
                continue

            path_part = unquote(parsed.path)
            fragment = unquote(parsed.fragment)
            if not path_part:
                target = source
            elif path_part.startswith("/"):
                target = root / path_part.lstrip("/")
            else:
                target = source.parent / path_part
            target = target.resolve()

            try:
                target.relative_to(root)
            except ValueError:
                errors.append(
                    f"{_relative_display(root, source)}:{line}: local target escapes repository: '{destination}'"
                )
                continue

            if not target.exists():
                errors.append(
                    f"{_relative_display(root, source)}:{line}: missing local target '{destination}'"
                )
                continue

            if fragment and target.is_file() and target.suffix.casefold() in {".md", ".markdown"}:
                anchors = anchor_cache.setdefault(target, _anchors(target))
                if fragment not in anchors:
                    errors.append(
                        f"{_relative_display(root, source)}:{line}: missing anchor '#{fragment}' in "
                        f"'{_relative_display(root, target)}'"
                    )

    return errors


def default_markdown_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    readme = root / "README.md"
    if readme.is_file():
        candidates.append(readme)
    docs = root / "docs"
    if docs.is_dir():
        candidates.extend(sorted(docs.rglob("*.md")))
    examples_readme = root / "examples" / "README.md"
    if examples_readme.is_file():
        candidates.append(examples_readme)
    return candidates


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check deterministic local Markdown links and anchors.")
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    root = args.root.resolve()
    files = default_markdown_files(root)
    errors = check_markdown_links(root, files)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Markdown links OK ({len(files)} files; external network links skipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
