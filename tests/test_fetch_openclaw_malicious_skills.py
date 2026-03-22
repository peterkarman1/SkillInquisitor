from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import yaml


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "fetch_openclaw_malicious_skills.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("fetch_openclaw_malicious_skills", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_find_upstream_skill_dir_matches_exact_skill_content(tmp_path):
    module = _load_module()
    repo = tmp_path / "openclaw"
    skill_dir = repo / "skills" / "alice" / "demo-skill"
    skill_dir.mkdir(parents=True)
    content = "---\nname: demo-skill\n---\n# Demo\n"
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    (skill_dir / "scripts").mkdir()
    (skill_dir / "scripts" / "payload.sh").write_text("echo hi\n", encoding="utf-8")

    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    _git(repo, "config", "user.email", "tests@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    matched = module.find_upstream_skill_dir(repo, "demo-skill", content)

    assert matched == "skills/alice/demo-skill"


def test_write_skill_snapshot_copies_full_upstream_skill_directory(tmp_path):
    module = _load_module()
    repo = tmp_path / "openclaw"
    skill_dir = repo / "skills" / "alice" / "demo-skill"
    skill_dir.mkdir(parents=True)
    content = "---\nname: demo-skill\n---\n# Demo\n"
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
    (skill_dir / "scripts").mkdir()
    (skill_dir / "scripts" / "payload.sh").write_text("echo hi\n", encoding="utf-8")
    (skill_dir / "references").mkdir()
    (skill_dir / "references" / "guide.md").write_text("guide\n", encoding="utf-8")
    (skill_dir / "_meta.json").write_text('{"owner":"alice"}\n', encoding="utf-8")

    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True, text=True)
    _git(repo, "config", "user.email", "tests@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    sample = {
        "slug": "openclaw-demo-skill-deadbe",
        "content": content,
        "dataset_id": "deadbeefcaf0",
        "family": "fake-prerequisite",
        "upstream_skill_dir": "skills/alice/demo-skill",
    }

    dataset_root = tmp_path / "dataset"
    module.write_skill_snapshot(dataset_root, sample, upstream_repo=repo)

    dest = dataset_root / "openclaw-demo-skill-deadbe"
    assert (dest / "SKILL.md").read_text(encoding="utf-8") == content
    assert (dest / "scripts" / "payload.sh").read_text(encoding="utf-8") == "echo hi\n"
    assert (dest / "references" / "guide.md").read_text(encoding="utf-8") == "guide\n"
    assert (dest / "_meta.json").read_text(encoding="utf-8") == '{"owner":"alice"}\n'

    benchmark_meta = yaml.safe_load((dest / "_meta.yaml").read_text(encoding="utf-8"))
    assert benchmark_meta["provenance"]["upstream_path"] == "skills/alice/demo-skill"


def test_build_manifest_entry_marks_benign_hf_samples_safe_without_attack_metadata():
    module = _load_module()
    sample = {
        "slug": "openclaw-demo-benign-cafeba",
        "dataset_id": "cafebabedead",
        "skill_name": "demo-benign",
        "family": "benign",
        "attack_categories": [],
        "severity": None,
        "difficulty": "medium",
        "tier": "full",
        "label": "benign",
    }

    entry = module.build_manifest_entry(sample)

    assert entry["ground_truth"]["verdict"] == "SAFE"
    assert entry["ground_truth"]["attack_categories"] == []
    assert "containment" not in entry
    assert "safe" in entry["metadata"]["tags"]


def test_update_manifest_replaces_existing_hf_mirror_entries(tmp_path):
    module = _load_module()
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "dataset_version": "4.0.1",
                "entries": [
                    {
                        "id": "obra-brainstorming",
                        "path": "skills/obra-brainstorming",
                        "ground_truth": {"verdict": "SAFE"},
                        "metadata": {"source_type": "github"},
                        "provenance": {"source_url": "https://github.com/obra/superpowers"},
                    },
                    {
                        "id": "openclaw-old-malicious",
                        "path": "skills/openclaw-old-malicious",
                        "ground_truth": {"verdict": "MALICIOUS"},
                        "metadata": {"source_type": "huggingface_mirror"},
                        "provenance": {"source_url": module.DATASET_CARD_URL, "source_ref": "hf:old"},
                    },
                    {
                        "id": "openclaw-old-benign",
                        "path": "skills/openclaw-old-benign",
                        "ground_truth": {"verdict": "SAFE"},
                        "metadata": {"source_type": "huggingface_mirror"},
                        "provenance": {"source_url": module.DATASET_CARD_URL, "source_ref": "hf:old-safe"},
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    replacement_entries = [
        {
            "id": "openclaw-new-malicious",
            "path": "skills/openclaw-new-malicious",
            "ground_truth": {"verdict": "MALICIOUS"},
            "metadata": {"source_type": "huggingface_mirror"},
            "provenance": {"source_url": module.DATASET_CARD_URL, "source_ref": "hf:new"},
        },
        {
            "id": "openclaw-new-benign",
            "path": "skills/openclaw-new-benign",
            "ground_truth": {"verdict": "SAFE"},
            "metadata": {"source_type": "huggingface_mirror"},
            "provenance": {"source_url": module.DATASET_CARD_URL, "source_ref": "hf:new-safe"},
        },
    ]

    module.update_manifest(manifest_path, replacement_entries)

    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    ids = [entry["id"] for entry in manifest["entries"]]
    assert ids == [
        "obra-brainstorming",
        "openclaw-new-malicious",
        "openclaw-new-benign",
    ]
