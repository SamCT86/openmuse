from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "markdown_links.py"


def load_checker():
    assert SCRIPT.exists(), "markdown link checker script is missing"
    spec = importlib.util.spec_from_file_location("markdown_links", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reports_missing_relative_target(tmp_path: Path) -> None:
    checker = load_checker()
    readme = tmp_path / "README.md"
    readme.write_text("See [missing](docs/missing.md)\n", encoding="utf-8")

    errors = checker.check_markdown_links(tmp_path, [readme])

    assert len(errors) == 1
    assert "docs/missing.md" in errors[0]
    assert "missing local target" in errors[0]


def test_accepts_encoded_spaces_and_local_image(tmp_path: Path) -> None:
    checker = load_checker()
    docs = tmp_path / "docs"
    assets = tmp_path / "assets"
    docs.mkdir()
    assets.mkdir()
    (docs / "guide with space.md").write_text("# Guide\n", encoding="utf-8")
    (assets / "diagram.png").write_bytes(b"png")
    readme = tmp_path / "README.md"
    readme.write_text(
        "[guide](docs/guide%20with%20space.md)\n![diagram](assets/diagram.png)\n",
        encoding="utf-8",
    )

    assert checker.check_markdown_links(tmp_path, [readme]) == []


def test_validates_markdown_anchors(tmp_path: Path) -> None:
    checker = load_checker()
    guide = tmp_path / "guide.md"
    guide.write_text("# Guide\n\n## Safety boundary\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text(
        "[ok](guide.md#safety-boundary)\n[bad](guide.md#missing-anchor)\n",
        encoding="utf-8",
    )

    errors = checker.check_markdown_links(tmp_path, [readme])

    assert len(errors) == 1
    assert "missing anchor '#missing-anchor'" in errors[0]


def test_ignores_external_network_links(tmp_path: Path) -> None:
    checker = load_checker()
    readme = tmp_path / "README.md"
    readme.write_text(
        "[site](https://example.com/docs#missing)\n[mail](mailto:test@example.com)\n",
        encoding="utf-8",
    )

    assert checker.check_markdown_links(tmp_path, [readme]) == []


def test_ignores_any_non_file_uri_scheme(tmp_path: Path) -> None:
    checker = load_checker()
    readme = tmp_path / "README.md"
    readme.write_text("[mirror](ftp://example.com/archive.md)\n", encoding="utf-8")

    assert checker.check_markdown_links(tmp_path, [readme]) == []


def test_ignores_links_inside_fenced_code(tmp_path: Path) -> None:
    checker = load_checker()
    readme = tmp_path / "README.md"
    readme.write_text("```md\n[example](missing.md)\n```\n", encoding="utf-8")

    assert checker.check_markdown_links(tmp_path, [readme]) == []


def test_checks_html_image_sources(tmp_path: Path) -> None:
    checker = load_checker()
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "logo.svg").write_text("<svg/>\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text('<img src="assets/logo.svg" alt="logo">\n', encoding="utf-8")

    assert checker.check_markdown_links(tmp_path, [readme]) == []
