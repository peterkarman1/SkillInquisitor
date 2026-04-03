import asyncio

import pytest

from skillinquisitor.models import ScanConfig, ScanResult, Skill
from skillinquisitor.service import ScanService


@pytest.mark.asyncio
async def test_scan_service_reuses_one_runtime_across_concurrent_scans(monkeypatch):
    runtime_ids: set[int] = set()
    max_inflight = 0
    inflight = 0

    async def fake_resolve_input(target, stdin_text=None, commit_sha=None, event_sink=None):
        return [Skill(path=f"{target}/SKILL.md", name=target)]

    async def fake_run_pipeline(*, skills, config, runtime=None, event_sink=None):
        nonlocal inflight, max_inflight
        runtime_ids.add(id(runtime))
        inflight += 1
        max_inflight = max(max_inflight, inflight)
        await asyncio.sleep(0.02)
        inflight -= 1
        return ScanResult(skills=skills, findings=[])

    monkeypatch.setattr("skillinquisitor.service.resolve_input", fake_resolve_input)
    monkeypatch.setattr("skillinquisitor.service.run_pipeline", fake_run_pipeline)

    service = ScanService(ScanConfig())
    try:
        first, second = await asyncio.gather(
            service.scan_target("skill-a"),
            service.scan_target("skill-b"),
        )
    finally:
        await service.close()

    assert len(runtime_ids) == 1
    assert max_inflight == 2
    assert first.skills[0].path == "skill-a/SKILL.md"
    assert second.skills[0].path == "skill-b/SKILL.md"


class CountingLeaseModel:
    def __init__(self, model_id: str, events: list[str]) -> None:
        self.model_id = model_id
        self._events = events

    def load(self) -> None:
        self._events.append(f"{self.model_id}:load")

    def generate_structured(self, prompt: str, max_tokens: int) -> dict[str, object]:
        self._events.append(f"{self.model_id}:generate:{prompt}")
        return {
            "disposition": "dispute",
            "severity": "info",
            "category": "behavioral",
            "message": "safe",
            "confidence": 0.9,
        }

    def unload(self) -> None:
        self._events.append(f"{self.model_id}:unload")


@pytest.mark.asyncio
async def test_scan_service_keeps_pooled_llama_loaded_until_host_closes_runtime(monkeypatch):
    events: list[str] = []

    monkeypatch.setattr(
        "skillinquisitor.runtime.build_code_analysis_model",
        lambda **kwargs: CountingLeaseModel("pooled-model", events),
    )
    monkeypatch.setattr(
        "skillinquisitor.runtime.resolve_model_file",
        lambda *args, **kwargs: None,
    )

    async def fake_resolve_input(target, stdin_text=None, commit_sha=None, event_sink=None):
        return [Skill(path=target, name=target)]

    async def fake_run_pipeline(*, skills, config, runtime=None, event_sink=None):
        lease = runtime.lease_llm_models(config)
        try:
            await asyncio.to_thread(lease.models[0].generate_structured, skills[0].path, 32)
            await asyncio.sleep(0.02)
            return ScanResult(skills=skills, findings=[])
        finally:
            lease.release()

    monkeypatch.setattr("skillinquisitor.service.resolve_input", fake_resolve_input)
    monkeypatch.setattr("skillinquisitor.service.run_pipeline", fake_run_pipeline)

    config = ScanConfig.model_validate(
        {
            "runtime": {
                "llm_lifecycle": "command",
                "llm_global_slots": 2,
                "llm_server_parallel_requests": 2,
                "llm_resident_model_limit": 1,
            },
            "layers": {
                "llm": {
                    "models": [{"id": "fixture://pooled", "runtime": "llama_cpp"}],
                    "repomix": {"enabled": False},
                }
            },
        }
    )
    service = ScanService(config)
    try:
        await asyncio.gather(
            service.scan_target("skill-a"),
            service.scan_target("skill-b"),
        )
        assert events == [
            "pooled-model:load",
            "pooled-model:generate:skill-a",
            "pooled-model:generate:skill-b",
        ]
    finally:
        await service.close()

    assert events == [
        "pooled-model:load",
        "pooled-model:generate:skill-a",
        "pooled-model:generate:skill-b",
        "pooled-model:unload",
    ]
