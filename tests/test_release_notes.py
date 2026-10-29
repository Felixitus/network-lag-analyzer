"""Release notes from the changelog: the workflow publishes them as they come out of here."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "release_notes", Path(__file__).resolve().parents[1] / ".github" / "scripts" / "release_notes.py")
rn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rn)


def project(tmp_path, version="1.5.0", changelog=None):
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "__init__.py").write_text(f'"""x"""\n__version__ = "{version}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog or (
        "# Changelog\n\n## [Unreleased]\n\n### Added\n- next\n\n"
        "## [1.5.0] - 2026-11-01\n\nSummary → line.\n\n### Fixed\n- one\n\n"
        "## [1.4.0] - 2026-10-29\n\n- older\n"), encoding="utf-8")
    return tmp_path


def test_the_notes_are_the_section_of_the_tag_without_its_heading(tmp_path):
    assert rn.notes("v1.5.0", project(tmp_path)) == "Summary → line.\n\n### Fixed\n- one\n"


def test_the_shipped_changelog_has_notes_for_the_current_version():
    import backend
    assert rn.notes(f"v{backend.__version__}").strip()


@pytest.mark.parametrize("tag", ["v1.5", "1.5.0", "v1.5.0-rc1", "v1.5.0;x", "", "v1.5.0\n"])
def test_a_tag_that_is_not_a_plain_version_is_refused(tmp_path, tag):
    with pytest.raises(ValueError, match="not a release tag"):
        rn.notes(tag, project(tmp_path))


def test_a_tag_that_does_not_match_the_code_is_refused(tmp_path):
    with pytest.raises(ValueError, match="does not match"):
        rn.notes("v1.4.0", project(tmp_path))


def test_a_version_without_a_changelog_section_is_refused(tmp_path):
    with pytest.raises(ValueError, match="no section"):
        rn.notes("v1.5.0", project(tmp_path, changelog="# Changelog\n\n## [Unreleased]\n- x\n"))
