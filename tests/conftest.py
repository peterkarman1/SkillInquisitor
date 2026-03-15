from __future__ import annotations

from dataclasses import dataclass
import asyncio
from pathlib import Path
from typing import Any

import pytest
import yaml

from skillinquisitor.models import Location, ScanResult, Skill


FIXTURES_ROOT = Path("tests/fixtures")
MANIFEST_PATH = FIXTURES_ROOT / "manifest.yaml"


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    path: str
    suite: str
    status: str
    expected: str
    checks: list[str]
    tags: list[str]


@dataclass(frozen=True)
class FixtureScope:
    layers: list[str]
    checks: list[str]


@dataclass(frozen=True)
class ExpectedFinding:
    rule_id: str
    layer: str
    category: str
    severity: str
    message: str
    location: dict[str, Any]


@dataclass(frozen=True)
class FixtureExpectation:
    schema_version: int
    verdict: str
    match_mode: str
    findings: list[ExpectedFinding]
    forbid_findings: list[dict[str, Any]]
    scope: FixtureScope | None = None


def _read_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"Expected mapping in YAML file: {path}")
    return raw


def _load_manifest() -> list[FixtureSpec]:
    data = _read_yaml(MANIFEST_PATH)
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError("tests/fixtures/manifest.yaml must contain a 'fixtures' list")

    specs: list[FixtureSpec] = []
    for entry in fixtures:
        if not isinstance(entry, dict):
            raise ValueError("Fixture manifest entries must be mappings")
        specs.append(
            FixtureSpec(
                id=str(entry["id"]),
                path=str(entry["path"]),
                suite=str(entry["suite"]),
                status=str(entry["status"]),
                expected=str(entry["expected"]),
                checks=list(entry.get("checks", [])),
                tags=list(entry.get("tags", [])),
            )
        )

    for spec in specs:
        fixture_dir = FIXTURES_ROOT / spec.path
        if not fixture_dir.exists():
            raise ValueError(f"Indexed fixture path does not exist: {fixture_dir}")
        if spec.status == "active" and not (fixture_dir / spec.expected).exists():
            raise ValueError(f"Active fixture is missing expectation file: {fixture_dir / spec.expected}")

    return specs


def _build_expectation(data: dict[str, Any]) -> FixtureExpectation:
    schema_version = data.get("schema_version")
    if schema_version != 1:
        raise ValueError("Fixture expectation schema_version must equal 1")

    match_mode = data.get("match_mode")
    if match_mode != "exact":
        raise ValueError("Fixture expectation match_mode must equal 'exact'")

    findings_data = data.get("findings", [])
    if not isinstance(findings_data, list):
        raise ValueError("Fixture expectation findings must be a list")
    findings = [
        ExpectedFinding(
            rule_id=str(item["rule_id"]),
            layer=str(item["layer"]),
            category=str(item["category"]),
            severity=str(item["severity"]),
            message=str(item["message"]),
            location=dict(item["location"]),
        )
        for item in findings_data
    ]

    forbid_findings = data.get("forbid_findings", [])
    if not isinstance(forbid_findings, list):
        raise ValueError("Fixture expectation forbid_findings must be a list")

    scope_data = data.get("scope")
    scope = None
    if scope_data is not None:
        if not isinstance(scope_data, dict):
            raise ValueError("Fixture expectation scope must be a mapping")
        layers = scope_data.get("layers", [])
        checks = scope_data.get("checks", [])
        if not isinstance(layers, list) or not isinstance(checks, list):
            raise ValueError("Fixture expectation scope.layers and scope.checks must be lists")
        scope = FixtureScope(layers=list(layers), checks=list(checks))

    return FixtureExpectation(
        schema_version=schema_version,
        verdict=str(data["verdict"]),
        match_mode=match_mode,
        findings=findings,
        forbid_findings=forbid_findings,
        scope=scope,
    )


def _load_expectation(fixture_path: str) -> FixtureExpectation:
    specs = {spec.path: spec for spec in _load_manifest()}
    spec = specs[fixture_path]
    data = _read_yaml(FIXTURES_ROOT / spec.path / spec.expected)
    return _build_expectation(data)


async def _scan_fixture(fixture_path: str) -> ScanResult:
    from skillinquisitor.config import ScanConfig
    from skillinquisitor.input import resolve_input
    from skillinquisitor.pipeline import run_pipeline

    skills = await resolve_input(str(FIXTURES_ROOT / fixture_path))
    return await run_pipeline(skills=skills, config=ScanConfig())


def _normalize_location(location: Location) -> dict[str, Any]:
    file_path = location.file_path
    if file_path:
        path_obj = Path(file_path)
        try:
            file_path = str(path_obj.relative_to(Path.cwd()))
        except ValueError:
            file_path = str(path_obj)
    return {
        "file_path": file_path,
        "start_line": location.start_line,
        "end_line": location.end_line,
    }


def _normalize_finding(finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "layer": finding.layer.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "message": finding.message,
        "location": _normalize_location(finding.location),
    }


def _normalized_expected_finding(finding: ExpectedFinding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "layer": finding.layer,
        "category": finding.category,
        "severity": finding.severity,
        "message": finding.message,
        "location": {
            "file_path": finding.location.get("file_path", ""),
            "start_line": finding.location.get("start_line"),
            "end_line": finding.location.get("end_line"),
        },
    }


def _apply_scope(expectation: FixtureExpectation, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if expectation.scope is None:
        return findings

    scoped: list[dict[str, Any]] = []
    for finding in findings:
        if expectation.scope.layers and finding["layer"] not in expectation.scope.layers:
            continue
        if expectation.scope.checks and finding["rule_id"] not in expectation.scope.checks:
            continue
        scoped.append(finding)
    return scoped


def _matches_partial(partial: dict[str, Any], finding: dict[str, Any]) -> bool:
    for key, value in partial.items():
        if key == "location" and isinstance(value, dict):
            if not _matches_partial(value, finding.get("location", {})):
                return False
            continue
        if finding.get(key) != value:
            return False
    return True


def _assert_matches(expectation: FixtureExpectation, result: ScanResult) -> None:
    if result.verdict != expectation.verdict:
        raise AssertionError(
            f"Verdict mismatch: expected {expectation.verdict!r}, got {result.verdict!r}"
        )

    actual = [_normalize_finding(finding) for finding in result.findings]
    actual_in_scope = _apply_scope(expectation, actual)
    expected = [_normalized_expected_finding(finding) for finding in expectation.findings]

    if expected != actual_in_scope:
        raise AssertionError(
            "Finding mismatch.\n"
            f"Expected in scope: {expected!r}\n"
            f"Actual in scope: {actual_in_scope!r}"
        )

    forbidden = [item for item in expectation.forbid_findings if isinstance(item, dict)]
    hits = [finding for finding in actual if any(_matches_partial(item, finding) for item in forbidden)]
    if hits:
        raise AssertionError(f"Forbidden findings present: {hits!r}")


@pytest.fixture
def load_fixture_manifest():
    return _load_manifest


@pytest.fixture
def load_active_fixture_specs(load_fixture_manifest):
    def _load(suite: str) -> list[FixtureSpec]:
        return [
            spec
            for spec in load_fixture_manifest()
            if spec.suite == suite and spec.status == "active"
        ]

    return _load


@pytest.fixture
def load_fixture_expectation():
    return _load_expectation


@pytest.fixture
def run_fixture_scan():
    def _run(fixture_path: str) -> ScanResult:
        return asyncio.run(_scan_fixture(fixture_path))

    return _run


@pytest.fixture
def build_expectation():
    def _build(
        *,
        verdict: str,
        findings: list[dict[str, Any]],
        scope: dict[str, list[str]] | None = None,
        forbid_findings: list[dict[str, Any]] | None = None,
    ) -> FixtureExpectation:
        data: dict[str, Any] = {
            "schema_version": 1,
            "verdict": verdict,
            "match_mode": "exact",
            "findings": findings,
            "forbid_findings": forbid_findings or [],
        }
        if scope is not None:
            data["scope"] = scope
        return _build_expectation(data)

    return _build


@pytest.fixture
def empty_scan_result():
    return ScanResult(skills=[Skill(path="tests/fixtures/empty", name="empty")], findings=[])


@pytest.fixture
def assert_scan_matches_expected(load_fixture_expectation):
    def _assert(expectation_or_path: str | FixtureExpectation, result: ScanResult) -> None:
        expectation = expectation_or_path
        if isinstance(expectation_or_path, str):
            expectation = load_fixture_expectation(expectation_or_path)
        _assert_matches(expectation, result)

    return _assert
