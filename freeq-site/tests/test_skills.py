"""
Validity checks for the repo-root `skills/` packages.

They live in this suite because it is the only pytest run in CI that sees the
repository root (the site renders the repo's docs), and a SKILL.md with broken
frontmatter fails *silently* in every consumer: Claude Code and pi just don't
load it, so nobody notices until an agent doesn't know something it should.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as site  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
EXPECTED = {"freeq", "freeq-api", "freeq-bots"}
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def _skills():
    return sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir())


def _frontmatter(text: str) -> dict:
    """Parse the leading `---` block. Deliberately strict — so is every loader."""
    assert text.startswith("---\n"), "SKILL.md must open with a --- frontmatter block"
    end = text.index("\n---\n", 3)
    fields = {}
    for line in text[4:end].splitlines():
        if not line.strip():
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def test_expected_skills_exist():
    assert SKILLS_DIR.is_dir(), "skills/ is missing"
    assert {p.name for p in _skills()} == EXPECTED


def test_each_skill_has_valid_frontmatter():
    for skill in _skills():
        path = skill / "SKILL.md"
        assert path.exists(), f"{skill.name} has no SKILL.md"
        fm = _frontmatter(path.read_text())
        assert fm.get("name") == skill.name, f"{skill.name}: frontmatter name must match the directory"
        desc = fm.get("description", "")
        # The description is the only thing a model sees when deciding whether
        # to load the skill, so a terse one is a skill that never gets used.
        assert len(desc) > 80, f"{skill.name}: description is too vague to route on"
        assert "Use when" in desc, f"{skill.name}: description should say when to use it"


def test_each_skill_has_a_body():
    for skill in _skills():
        text = (skill / "SKILL.md").read_text()
        body = text.split("\n---\n", 1)[1]
        assert body.lstrip().startswith("#"), f"{skill.name}: body should start with a heading"
        assert len(body) > 500, f"{skill.name}: body is too thin to be useful"


def test_cross_links_between_skills_resolve():
    for skill in _skills():
        text = (skill / "SKILL.md").read_text()
        for ref in re.findall(r"`skills/([a-z-]+)`", text):
            assert (SKILLS_DIR / ref).is_dir(), f"{skill.name} references missing skills/{ref}"


def test_doc_links_point_at_docs_that_exist():
    """Links into the docs site must name a real slug, not a guessed one."""
    broken = []
    for skill in _skills():
        text = (skill / "SKILL.md").read_text()
        for href in LINK_RE.findall(text):
            m = re.match(r"https://freeq\.at/docs/([a-z0-9-]+)\.md$", href)
            if not m:
                continue
            if site._doc_path(m.group(1)) is None:
                broken.append(f"{skill.name} → {href}")
    assert not broken, f"skills link to unmapped docs: {broken}"


def test_repo_llms_txt_advertises_the_skills():
    body = (REPO_ROOT / "llms.txt").read_text()
    assert "skills/" in body, "llms.txt should point agents at the skills"
