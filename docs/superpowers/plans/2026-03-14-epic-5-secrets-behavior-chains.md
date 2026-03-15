# Epic 5 Secrets and Behavior Chains Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Epic 5's deterministic secrets, exfiltration, and behavior-chain coverage so SkillInquisitor can detect sensitive reads, suspicious environment access, outbound sends, dynamic execution, and skill-level attack chains across markdown and code artifacts.

**Architecture:** Add two new deterministic rule modules: `secrets.py` for D-7 and D-8 and `behavioral.py` for D-9, D-10, and D-19. Keep component rules local and composable by emitting ordinary deterministic findings with `action_flags`, then add a deterministic postprocessor that synthesizes D-19 chain findings at skill scope with references back to the component evidence.

**Tech Stack:** Python 3.13, Typer, Pydantic v2, pytest, existing deterministic rule engine, existing regression harness

---

## File Structure

### Files to Create

- `src/skillinquisitor/detectors/rules/secrets.py`
- `src/skillinquisitor/detectors/rules/behavioral.py`
- `tests/fixtures/deterministic/secrets/D-7-sensitive-files/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-7-sensitive-files/scripts/read_secret.py`
- `tests/fixtures/deterministic/secrets/D-7-sensitive-files/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/scripts/fetch_metadata.py`
- `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/scripts/dump_keys.py`
- `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/scripts/env_dump.py`
- `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-9-network-send/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-9-network-send/scripts/send.py`
- `tests/fixtures/deterministic/secrets/D-9-network-send/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/scripts/run_dynamic.py`
- `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-19-read-send-chain/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-19-read-send-chain/scripts/send.py`
- `tests/fixtures/deterministic/secrets/D-19-read-send-chain/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/scripts/run_payload.py`
- `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/expected.yaml`
- `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/SKILL.md`
- `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/scripts/publish.py`
- `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/expected.yaml`
- `tests/fixtures/deterministic/secrets/safe-docs-env-mention/SKILL.md`
- `tests/fixtures/deterministic/secrets/safe-docs-env-mention/expected.yaml`
- `tests/fixtures/deterministic/secrets/safe-env-config/SKILL.md`
- `tests/fixtures/deterministic/secrets/safe-env-config/scripts/config.py`
- `tests/fixtures/deterministic/secrets/safe-env-config/expected.yaml`
- `tests/fixtures/deterministic/secrets/safe-health-check/SKILL.md`
- `tests/fixtures/deterministic/secrets/safe-health-check/scripts/check.py`
- `tests/fixtures/deterministic/secrets/safe-health-check/expected.yaml`

### Files to Modify

- `src/skillinquisitor/models.py`
- `src/skillinquisitor/detectors/rules/engine.py`
- `src/skillinquisitor/pipeline.py`
- `tests/test_config.py`
- `tests/test_deterministic.py`
- `tests/test_pipeline.py`
- `tests/test_cli.py`
- `tests/fixtures/manifest.yaml`
- `README.md`
- `CHANGELOG.md`
- `TODO.md`
- `docs/requirements/business-requirements.md`
- `docs/requirements/architecture.md`

### Responsibilities

- `models.py`
  - Add built-in default chain definitions if they are not already supplied through config defaults.
- `engine.py`
  - Register Epic 5 rule families and add the deterministic postprocessing hook needed for D-19, including single-rule testing support for postprocessed rules.
- `secrets.py`
  - Implement sensitive resource and environment-secret detection plus `READ_SENSITIVE` / `SSRF_METADATA` tagging.
- `behavioral.py`
  - Implement outbound send and dynamic execution detection plus `NETWORK_SEND` / `EXEC_DYNAMIC` tagging and D-19 chain synthesis.
- `pipeline.py`
  - Preserve stable deterministic layer metadata while flowing richer Epic 5 findings through the existing pipeline.
- `tests/test_config.py`
  - Lock default chain configuration behavior.
- `tests/test_deterministic.py`
  - Lock Epic 5 fixture behavior through the regression harness.
- `tests/test_pipeline.py`
  - Prove chain synthesis works across files within one skill.
- `tests/test_cli.py`
  - Prove Epic 5 rule visibility and single-rule execution behavior, including D-19 postprocessed rules.
- `tests/fixtures/deterministic/secrets/*`
  - Provide positive, negative, markdown, code, same-file, and cross-file cases for Epic 5.

## Chunk 1: Engine and Configuration Groundwork

### Task 1: Add built-in default behavior chains to the shared config model

**Files:**
- Modify: `src/skillinquisitor/models.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write the failing config test**

```python
from skillinquisitor.config import load_config


def test_load_config_includes_default_behavior_chains(tmp_path):
    config = load_config(project_root=tmp_path, env={}, cli_overrides={})

    chain_names = {chain.name for chain in config.chains}
    assert "Data Exfiltration" in chain_names
    assert "Credential Theft" in chain_names
    assert "Cloud Metadata SSRF" in chain_names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py::test_load_config_includes_default_behavior_chains -v`
Expected: FAIL because `ScanConfig.chains` is empty by default today.

- [ ] **Step 3: Write the minimal implementation**

```python
def _default_chains() -> list[ChainConfig]:
    return [
        ChainConfig(name="Data Exfiltration", required=["READ_SENSITIVE", "NETWORK_SEND"], severity=Severity.CRITICAL),
        ChainConfig(name="Credential Theft", required=["READ_SENSITIVE", "EXEC_DYNAMIC"], severity=Severity.CRITICAL),
        ChainConfig(name="Cloud Metadata SSRF", required=["SSRF_METADATA", "NETWORK_SEND"], severity=Severity.CRITICAL),
    ]


class ScanConfig(BaseModel):
    ...
    chains: list[ChainConfig] = Field(default_factory=_default_chains)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py::test_load_config_includes_default_behavior_chains -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/models.py tests/test_config.py
git commit -m "feat: add default epic 5 behavior chains"
```

### Task 2: Add Epic 5 rule registration and postprocessor plumbing to the deterministic engine

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Create: `src/skillinquisitor/detectors/rules/secrets.py`
- Create: `src/skillinquisitor/detectors/rules/behavioral.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write the failing registry and CLI tests**

```python
from skillinquisitor.detectors.rules import build_rule_registry
from skillinquisitor.models import ScanConfig


def test_rule_registry_includes_epic5_rules():
    registry = build_rule_registry(ScanConfig())

    assert registry.get("D-7A") is not None
    assert registry.get("D-10A") is not None
    assert registry.get("D-19A") is not None
```

```python
def test_rules_list_outputs_registered_epic5_rules():
    result = runner.invoke(app, ["rules", "list"])

    assert result.exit_code == 0
    assert "D-7A" in result.stdout
    assert "D-19A" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py::test_rule_registry_includes_epic5_rules tests/test_cli.py::test_rules_list_outputs_registered_epic5_rules -v`
Expected: FAIL because Epic 5 modules are not registered yet.

- [ ] **Step 3: Write the minimal implementation**

```python
def build_rule_registry(config: ScanConfig) -> RuleRegistry:
    from skillinquisitor.detectors.rules.behavioral import register_behavioral_rules
    from skillinquisitor.detectors.rules.encoding import register_encoding_rules
    from skillinquisitor.detectors.rules.secrets import register_secrets_rules
    from skillinquisitor.detectors.rules.unicode import register_unicode_rules

    registry = RuleRegistry()
    register_unicode_rules(registry)
    register_encoding_rules(registry)
    register_secrets_rules(registry)
    register_behavioral_rules(registry)
    ...
```

```python
def run_registered_rules(...):
    ...
    findings.extend(run_encoding_postprocessors(...))
    findings.extend(run_behavioral_postprocessors(...))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py::test_rule_registry_includes_epic5_rules tests/test_cli.py::test_rules_list_outputs_registered_epic5_rules -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/engine.py src/skillinquisitor/detectors/rules/secrets.py src/skillinquisitor/detectors/rules/behavioral.py tests/test_pipeline.py tests/test_cli.py
git commit -m "feat: scaffold epic 5 rule families"
```

## Chunk 2: D-7 and D-8 Component Detection

### Task 3: Add Epic 5 fixture coverage for sensitive resources and environment secrets

**Files:**
- Create: `tests/fixtures/deterministic/secrets/D-7-sensitive-files/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-7-sensitive-files/scripts/read_secret.py`
- Create: `tests/fixtures/deterministic/secrets/D-7-sensitive-files/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/scripts/fetch_metadata.py`
- Create: `tests/fixtures/deterministic/secrets/D-7-metadata-endpoints/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/scripts/dump_keys.py`
- Create: `tests/fixtures/deterministic/secrets/D-8-known-secret-vars/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/scripts/env_dump.py`
- Create: `tests/fixtures/deterministic/secrets/D-8-generic-env-enum/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/safe-docs-env-mention/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/safe-docs-env-mention/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/safe-env-config/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/safe-env-config/scripts/config.py`
- Create: `tests/fixtures/deterministic/secrets/safe-env-config/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Add the failing fixture harness coverage**

```python
@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-7-sensitive-files",
        "deterministic/secrets/D-7-metadata-endpoints",
        "deterministic/secrets/D-8-known-secret-vars",
        "deterministic/secrets/D-8-generic-env-enum",
        "deterministic/secrets/safe-docs-env-mention",
        "deterministic/secrets/safe-env-config",
    ],
)
def test_secrets_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_deterministic.py -k "secrets_rule_fixtures" -v`
Expected: FAIL because the new fixtures are indexed but Epic 5 rules do not emit the expected findings yet.

- [ ] **Step 3: Write the fixture files and manifest entries**

```yaml
schema_version: 1
verdict: MEDIUM RISK
match_mode: exact
scope:
  layers: [deterministic]
  checks: [D-7A]
findings:
  - rule_id: D-7A
    layer: deterministic
    category: credential_theft
    severity: high
    message: Sensitive credential path reference detected
    location:
      file_path: tests/fixtures/deterministic/secrets/D-7-sensitive-files/scripts/read_secret.py
      start_line: 2
      end_line: 2
forbid_findings: []
```

- [ ] **Step 4: Re-run tests and confirm they still fail for the right reason**

Run: `uv run pytest tests/test_deterministic.py -k "secrets_rule_fixtures" -v`
Expected: FAIL with missing expected findings, proving the harness and fixtures are wired correctly.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/deterministic/secrets tests/fixtures/manifest.yaml tests/test_deterministic.py
git commit -m "test: add epic 5 secrets fixture coverage"
```

### Task 4: Implement D-7 and D-8 in `secrets.py`

**Files:**
- Create: `src/skillinquisitor/detectors/rules/secrets.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Add focused failing unit tests for action flags**

```python
from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanConfig
from skillinquisitor.pipeline import run_pipeline


@pytest.mark.asyncio
async def test_pipeline_tags_metadata_access_with_ssrf_metadata(tmp_path):
    skill_dir = tmp_path / "skill"
    script_dir = skill_dir / "scripts"
    script_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# test", encoding="utf-8")
    (script_dir / "fetch_metadata.py").write_text(
        'import requests\nrequests.get("http://169.254.169.254/latest/meta-data/")\n',
        encoding="utf-8",
    )

    skills = await resolve_input(str(skill_dir))
    result = await run_pipeline(skills=skills, config=ScanConfig())

    finding = next(f for f in result.findings if f.rule_id == "D-7B")
    assert "SSRF_METADATA" in finding.action_flags
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_tags_metadata_access_with_ssrf_metadata tests/test_deterministic.py -k "secrets_rule_fixtures" -v`
Expected: FAIL because D-7 and D-8 are not implemented yet.

- [ ] **Step 3: Write the minimal implementation**

```python
SENSITIVE_PATH_PATTERN = re.compile(r"\.(env|npmrc|pypirc)\b|\.ssh/|\.aws/|\.gnupg/", re.IGNORECASE)
METADATA_PATTERN = re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.IGNORECASE)
SECRET_ENV_PATTERN = re.compile(r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN")


def register_secrets_rules(registry: RuleRegistry) -> None:
    registry.register(... rule_id="D-7A", evaluator=_detect_sensitive_paths)
    registry.register(... rule_id="D-7B", evaluator=_detect_metadata_targets)
    registry.register(... rule_id="D-8A", evaluator=_detect_known_secret_env_vars)
    registry.register(... rule_id="D-8B", evaluator=_detect_env_enumeration)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_tags_metadata_access_with_ssrf_metadata tests/test_deterministic.py -k "secrets_rule_fixtures" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/secrets.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: add epic 5 secrets detectors"
```

## Chunk 3: D-9 and D-10 Component Detection

### Task 5: Add fixture coverage for network-send and dynamic-exec detection

**Files:**
- Create: `tests/fixtures/deterministic/secrets/D-9-network-send/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-9-network-send/scripts/send.py`
- Create: `tests/fixtures/deterministic/secrets/D-9-network-send/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/scripts/run_dynamic.py`
- Create: `tests/fixtures/deterministic/secrets/D-10-dynamic-exec/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/safe-health-check/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/safe-health-check/scripts/check.py`
- Create: `tests/fixtures/deterministic/secrets/safe-health-check/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`

- [ ] **Step 1: Add the failing fixture harness coverage**

```python
@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-9-network-send",
        "deterministic/secrets/D-10-dynamic-exec",
        "deterministic/secrets/safe-health-check",
    ],
)
def test_behavioral_component_rule_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_deterministic.py -k "behavioral_component_rule_fixtures" -v`
Expected: FAIL because D-9 and D-10 are not implemented yet.

- [ ] **Step 3: Write the fixture files and manifest entries**

```yaml
schema_version: 1
verdict: MEDIUM RISK
match_mode: exact
scope:
  layers: [deterministic]
  checks: [D-9A]
findings:
  - rule_id: D-9A
    layer: deterministic
    category: data_exfiltration
    severity: medium
    message: Outbound network send behavior detected
    location:
      file_path: tests/fixtures/deterministic/secrets/D-9-network-send/scripts/send.py
      start_line: 2
      end_line: 2
forbid_findings: []
```

- [ ] **Step 4: Re-run tests and confirm they still fail for the right reason**

Run: `uv run pytest tests/test_deterministic.py -k "behavioral_component_rule_fixtures" -v`
Expected: FAIL with missing expected findings.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/deterministic/secrets tests/fixtures/manifest.yaml tests/test_deterministic.py
git commit -m "test: add epic 5 behavioral component fixtures"
```

### Task 6: Implement D-9 and D-10 in `behavioral.py`

**Files:**
- Create: `src/skillinquisitor/detectors/rules/behavioral.py`
- Modify: `tests/test_pipeline.py`

- [ ] **Step 1: Add focused failing pipeline tests for action flags**

```python
@pytest.mark.asyncio
async def test_pipeline_tags_network_send_component(tmp_path):
    ...
    finding = next(f for f in result.findings if f.rule_id == "D-9A")
    assert "NETWORK_SEND" in finding.action_flags


@pytest.mark.asyncio
async def test_pipeline_tags_exec_dynamic_component(tmp_path):
    ...
    finding = next(f for f in result.findings if f.rule_id == "D-10A")
    assert "EXEC_DYNAMIC" in finding.action_flags
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -k "network_send_component or exec_dynamic_component" tests/test_deterministic.py -k "behavioral_component_rule_fixtures" -v`
Expected: FAIL because behavioral component rules are not implemented yet.

- [ ] **Step 3: Write the minimal implementation**

```python
NETWORK_PATTERN = re.compile(r"\bcurl\b|\bwget\b|requests\.(get|post)|urllib|http\.client|socket|fetch\(", re.IGNORECASE)
EXEC_PATTERN = re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|__import__\s*\(|subprocess|os\.system|popen|bash\s+-c|sh\s+-c|`[^`]+`", re.IGNORECASE)


def register_behavioral_rules(registry: RuleRegistry) -> None:
    registry.register(... rule_id="D-9A", evaluator=_detect_network_send)
    registry.register(... rule_id="D-10A", evaluator=_detect_exec_dynamic)
    registry.register(... rule_id="D-19A", evaluator=_noop_segment_rule)
    registry.register(... rule_id="D-19B", evaluator=_noop_segment_rule)
    registry.register(... rule_id="D-19C", evaluator=_noop_segment_rule)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py -k "network_send_component or exec_dynamic_component" tests/test_deterministic.py -k "behavioral_component_rule_fixtures" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/behavioral.py tests/test_pipeline.py tests/test_deterministic.py
git commit -m "feat: add epic 5 behavioral component detectors"
```

## Chunk 4: D-19 Chain Synthesis, Verification, and Docs Sync

### Task 7: Add fixture and unit coverage for D-19 behavior chains

**Files:**
- Create: `tests/fixtures/deterministic/secrets/D-19-read-send-chain/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-19-read-send-chain/scripts/send.py`
- Create: `tests/fixtures/deterministic/secrets/D-19-read-send-chain/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/scripts/run_payload.py`
- Create: `tests/fixtures/deterministic/secrets/D-19-read-exec-chain/expected.yaml`
- Create: `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/SKILL.md`
- Create: `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/scripts/publish.py`
- Create: `tests/fixtures/deterministic/secrets/D-19-metadata-send-chain/expected.yaml`
- Modify: `tests/fixtures/manifest.yaml`
- Modify: `tests/test_deterministic.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add the failing chain tests**

```python
@pytest.mark.asyncio
async def test_pipeline_emits_critical_chain_when_code_and_markdown_combine(tmp_path):
    ...
    finding = next(f for f in result.findings if f.rule_id == "D-19A")
    assert finding.severity.value == "critical"
    assert finding.references
```

```python
def test_rules_test_runs_postprocessed_d19_rule():
    result = runner.invoke(app, ["rules", "test", "D-19A", "tests/fixtures/deterministic/secrets/D-19-read-send-chain"])

    assert result.exit_code == 1
    assert "D-19A" in result.stdout
```

```python
@pytest.mark.parametrize(
    "fixture_id",
    [
        "deterministic/secrets/D-19-read-send-chain",
        "deterministic/secrets/D-19-read-exec-chain",
        "deterministic/secrets/D-19-metadata-send-chain",
    ],
)
def test_behavior_chain_fixtures(run_fixture_scan, assert_scan_matches_expected, fixture_id):
    result = run_fixture_scan(fixture_id)
    assert_scan_matches_expected(fixture_id, result)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_critical_chain_when_code_and_markdown_combine tests/test_cli.py::test_rules_test_runs_postprocessed_d19_rule tests/test_deterministic.py -k "behavior_chain_fixtures" -v`
Expected: FAIL because D-19 postprocessing and single-rule postprocessor support are not implemented yet.

- [ ] **Step 3: Write the fixture files and expectations**

```yaml
schema_version: 1
verdict: MEDIUM RISK
match_mode: exact
scope:
  layers: [deterministic]
  checks: [D-7A, D-9A, D-19A]
findings:
  - rule_id: D-7A
    layer: deterministic
    category: credential_theft
    severity: medium
    message: Sensitive credential path reference detected
    location:
      file_path: tests/fixtures/deterministic/secrets/D-19-read-send-chain/SKILL.md
      start_line: 4
      end_line: 4
  - rule_id: D-9A
    layer: deterministic
    category: data_exfiltration
    severity: medium
    message: Outbound network send behavior detected
    location:
      file_path: tests/fixtures/deterministic/secrets/D-19-read-send-chain/scripts/send.py
      start_line: 2
      end_line: 2
  - rule_id: D-19A
    layer: deterministic
    category: data_exfiltration
    severity: critical
    message: Behavior chain detected: Data Exfiltration
    location:
      file_path: tests/fixtures/deterministic/secrets/D-19-read-send-chain/SKILL.md
      start_line: 1
      end_line: 1
forbid_findings: []
```

- [ ] **Step 4: Re-run tests and confirm they still fail for the right reason**

Run: `uv run pytest tests/test_pipeline.py::test_pipeline_emits_critical_chain_when_code_and_markdown_combine tests/test_cli.py::test_rules_test_runs_postprocessed_d19_rule tests/test_deterministic.py -k "behavior_chain_fixtures" -v`
Expected: FAIL with missing D-19 findings.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/deterministic/secrets tests/fixtures/manifest.yaml tests/test_deterministic.py tests/test_pipeline.py tests/test_cli.py
git commit -m "test: add epic 5 behavior chain coverage"
```

### Task 8: Implement D-19 chain synthesis and single-rule postprocessor execution

**Files:**
- Modify: `src/skillinquisitor/detectors/rules/behavioral.py`
- Modify: `src/skillinquisitor/detectors/rules/engine.py`
- Modify: `src/skillinquisitor/pipeline.py`
- Modify: `tests/test_pipeline.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add one more focused failing unit test for markdown-only severity**

```python
@pytest.mark.asyncio
async def test_pipeline_emits_high_chain_for_markdown_only_exfiltration(tmp_path):
    ...
    finding = next(f for f in result.findings if f.rule_id == "D-19A")
    assert finding.severity.value == "high"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -k "critical_chain_when_code_and_markdown_combine or markdown_only_exfiltration" tests/test_cli.py::test_rules_test_runs_postprocessed_d19_rule tests/test_deterministic.py -k "behavior_chain_fixtures" -v`
Expected: FAIL because chain synthesis is still missing.

- [ ] **Step 3: Write the minimal implementation**

```python
def run_behavioral_postprocessors(
    skills: list[Skill],
    findings: list[Finding],
    config: ScanConfig,
    only_rule_id: str | None = None,
) -> list[Finding]:
    chain_findings: list[Finding] = []
    findings_by_skill = _group_findings_by_skill(skills, findings)

    for skill, component_findings in findings_by_skill:
        for chain in config.chains:
            if only_rule_id is not None and _chain_rule_id(chain) != only_rule_id:
                continue
            matched = _select_component_evidence(component_findings, chain.required)
            if not matched:
                continue
            chain_findings.append(_build_chain_finding(skill, chain, matched))

    return chain_findings
```

```python
def run_registered_rules(...):
    ...
    findings.extend(run_encoding_postprocessors(skills, findings))
    findings.extend(run_behavioral_postprocessors(skills, findings, config, only_rule_id=only_rule_id))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py -k "critical_chain_when_code_and_markdown_combine or markdown_only_exfiltration" tests/test_cli.py::test_rules_test_runs_postprocessed_d19_rule tests/test_deterministic.py -k "behavior_chain_fixtures" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/skillinquisitor/detectors/rules/behavioral.py src/skillinquisitor/detectors/rules/engine.py src/skillinquisitor/pipeline.py tests/test_pipeline.py tests/test_cli.py tests/test_deterministic.py
git commit -m "feat: add epic 5 behavior chain synthesis"
```

### Task 9: Sync documentation and verify the full Epic 5 branch

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `TODO.md`
- Modify: `docs/requirements/business-requirements.md`
- Modify: `docs/requirements/architecture.md`

- [ ] **Step 1: Update the docs to match the implementation**

```md
- README: mention Epic 5 deterministic secrets and behavior-chain coverage
- CHANGELOG: add Epic 5 feature and fixture corpus entries under [Unreleased]
- TODO: mark Epic 5 items complete with files changed and key decisions
- BRD / architecture: sync any rule IDs, chain behavior, or CLI semantics that changed during implementation
```

- [ ] **Step 2: Run the focused verification commands**

Run: `uv run pytest tests/test_config.py tests/test_pipeline.py tests/test_cli.py tests/test_deterministic.py -q`
Expected: PASS

Run: `uv run pytest tests/test_deterministic.py -k "secrets or behavior_chain" -v`
Expected: PASS

- [ ] **Step 3: Run the full suite**

Run: `./scripts/run-test-suite.sh`
Expected: PASS

- [ ] **Step 4: Review git state and confirm docs are included**

Run: `git status --short`
Expected: only Epic 5 implementation files remain staged or modified for the final commit.

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md TODO.md docs/requirements/business-requirements.md docs/requirements/architecture.md
git add src/skillinquisitor tests
git commit -m "feat: implement epic 5 secrets and behavior chains"
```
