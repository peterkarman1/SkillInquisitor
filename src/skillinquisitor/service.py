from __future__ import annotations

import asyncio

from skillinquisitor.input import resolve_input
from skillinquisitor.models import ScanConfig, ScanResult, Skill
from skillinquisitor.pipeline import merge_scan_results, run_pipeline
from skillinquisitor.progress import ProgressSink, emit_progress
from skillinquisitor.runtime import ScanRuntime


async def scan_skills(
    *,
    skills: list[Skill],
    config: ScanConfig,
    runtime: ScanRuntime | None = None,
    workers: int | None = None,
    event_sink: ProgressSink | None = None,
    target: str | None = None,
) -> ScanResult:
    active_runtime = runtime or ScanRuntime.from_config(config, event_sink=event_sink)
    owns_runtime = runtime is None
    worker_count = max(1, workers if workers is not None else config.runtime.scan_workers)
    scan_target = target or (skills[0].path if skills else "<empty>")

    emit_progress(event_sink, "scan.started", target=scan_target, workers=worker_count)
    try:
        if worker_count <= 1 or len(skills) <= 1:
            if skills:
                skill = skills[0]
                emit_progress(
                    event_sink,
                    "scan.skill.started",
                    index=1,
                    total=1,
                    skill_name=skill.name,
                    skill_path=skill.path,
                )
            result = await run_pipeline(skills=skills, config=config, runtime=active_runtime, event_sink=event_sink)
            emit_progress(
                event_sink,
                "scan.skill.completed",
                index=1,
                total=1,
                skill_name=skills[0].name if skills else scan_target,
                skill_path=skills[0].path if skills else scan_target,
                risk_label=result.risk_label.value,
                binary_label=result.binary_label,
                finding_count=len(result.findings),
            )
            emit_progress(event_sink, "scan.completed", skills=len(skills))
            return result

        semaphore = asyncio.Semaphore(worker_count)
        results: list[ScanResult | None] = [None] * len(skills)

        async def run_single(index: int, skill: Skill) -> None:
            async with semaphore:
                emit_progress(
                    event_sink,
                    "scan.skill.started",
                    index=index + 1,
                    total=len(skills),
                    skill_name=skill.name,
                    skill_path=skill.path,
                )
                results[index] = await run_pipeline(
                    skills=[skill],
                    config=config,
                    runtime=active_runtime,
                    event_sink=event_sink,
                )
                result = results[index]
                if result is not None:
                    emit_progress(
                        event_sink,
                        "scan.skill.completed",
                        index=index + 1,
                        total=len(skills),
                        skill_name=skill.name,
                        skill_path=skill.path,
                        risk_label=result.risk_label.value,
                        binary_label=result.binary_label,
                        finding_count=len(result.findings),
                    )

        await asyncio.gather(*(run_single(index, skill) for index, skill in enumerate(skills)))
        merged = merge_scan_results([result for result in results if result is not None], config)
        emit_progress(event_sink, "scan.completed", skills=len(skills))
        return merged
    finally:
        if owns_runtime:
            await active_runtime.close()


async def scan_target(
    *,
    target: str,
    config: ScanConfig,
    runtime: ScanRuntime | None = None,
    workers: int | None = None,
    commit_sha: str | None = None,
    event_sink: ProgressSink | None = None,
) -> ScanResult:
    skills = await resolve_input(target, commit_sha=commit_sha, event_sink=event_sink)
    return await scan_skills(
        skills=skills,
        config=config,
        runtime=runtime,
        workers=workers,
        event_sink=event_sink,
        target=target,
    )


class ScanService:
    def __init__(
        self,
        config: ScanConfig,
        *,
        event_sink: ProgressSink | None = None,
        runtime: ScanRuntime | None = None,
    ) -> None:
        self.config = config
        self.event_sink = event_sink
        self.runtime = runtime or ScanRuntime.from_config(config, event_sink=event_sink)
        self._owns_runtime = runtime is None
        self._closed = False

    async def scan_target(
        self,
        target: str,
        *,
        workers: int | None = None,
        commit_sha: str | None = None,
        event_sink: ProgressSink | None = None,
    ) -> ScanResult:
        return await scan_target(
            target=target,
            config=self.config,
            runtime=self.runtime,
            workers=workers,
            commit_sha=commit_sha,
            event_sink=event_sink or self.event_sink,
        )

    async def scan_skills(
        self,
        skills: list[Skill],
        *,
        workers: int | None = None,
        event_sink: ProgressSink | None = None,
        target: str | None = None,
    ) -> ScanResult:
        return await scan_skills(
            skills=skills,
            config=self.config,
            runtime=self.runtime,
            workers=workers,
            event_sink=event_sink or self.event_sink,
            target=target,
        )

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_runtime:
            await self.runtime.close()

    async def __aenter__(self) -> "ScanService":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
