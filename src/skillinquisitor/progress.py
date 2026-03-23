from __future__ import annotations

from collections.abc import Callable


ProgressSink = Callable[..., None]


def emit_progress(event_sink: ProgressSink | None, event_name: str, **fields: object) -> None:
    if event_sink is None:
        return
    event_sink(event_name, **fields)


class ProgressRenderer:
    def __init__(self, writer: Callable[[str], None], *, verbose: bool = False) -> None:
        self._writer = writer
        self._verbose = verbose

    def __call__(self, event_name: str, **fields: object) -> None:
        message = self._render(event_name, **fields)
        if message:
            self._writer(message)

    def _render(self, event_name: str, **fields: object) -> str | None:
        if event_name == "scan.started":
            return f"[scan] resolving {fields.get('target')} (workers={fields.get('workers', 1)})"
        if event_name == "input.github.clone.started":
            ref = fields.get("ref")
            ref_suffix = f" @ {ref}" if ref else ""
            return f"[input] cloning {fields.get('owner')}/{fields.get('repo')}{ref_suffix}"
        if event_name == "input.github.clone.completed":
            return f"[input] cloned to {fields.get('path')}"
        if event_name == "input.discovered":
            count = fields.get("skills", 0)
            root = fields.get("root")
            label = "skill" if count == 1 else "skills"
            return f"[input] discovered {count} {label} in {root}"
        if event_name == "scan.skill.started":
            index = fields.get("index")
            total = fields.get("total")
            name = fields.get("skill_name") or fields.get("skill_path")
            return f"[scan {index}/{total}] {name}"
        if event_name == "scan.skill.completed":
            index = fields.get("index")
            total = fields.get("total")
            name = fields.get("skill_name") or fields.get("skill_path")
            return (
                f"[scan {index}/{total}] {name} "
                f"{fields.get('risk_label')} {fields.get('binary_label')} "
                f"({fields.get('finding_count', 0)} findings)"
            )
        if event_name == "scan.completed":
            return f"[scan] complete: {fields.get('skills', 0)} skills"
        if event_name == "benchmark.started":
            return (
                f"[benchmark] {fields.get('tier')} {fields.get('dataset_profile')} started: "
                f"{fields.get('total_skills')} skills, concurrency={fields.get('concurrency')}"
            )
        if event_name == "benchmark.skill.completed":
            elapsed_ms = float(fields.get("elapsed_ms", 0.0) or 0.0)
            return (
                f"[benchmark {fields.get('index')}/{fields.get('total')}] {fields.get('skill_id')} "
                f"{fields.get('risk_label')} {fields.get('binary_label')} {elapsed_ms / 1000.0:.1f}s"
            )
        if event_name == "benchmark.completed":
            return (
                f"[benchmark] complete: {fields.get('total_skills')} skills in "
                f"{float(fields.get('wall_clock_seconds', 0.0) or 0.0):.1f}s"
            )

        if not self._verbose:
            return None

        if event_name == "pipeline.started":
            return f"[pipeline] starting {fields.get('skills', 0)} skill(s)"
        if event_name == "pipeline.deterministic.completed":
            return f"[pipeline] deterministic: {fields.get('findings', 0)} findings"
        if event_name == "pipeline.ml.started":
            return f"[pipeline] ml start: {fields.get('segments', 0)} candidate segments"
        if event_name == "pipeline.ml.completed":
            return f"[pipeline] ml done: {fields.get('findings', 0)} findings"
        if event_name == "pipeline.ml.skipped":
            return f"[pipeline] ml skipped: {fields.get('reason')}"
        if event_name == "pipeline.llm.started":
            return f"[pipeline] llm start: {fields.get('targets', 0)} targets"
        if event_name == "pipeline.llm.completed":
            return f"[pipeline] llm done: {fields.get('findings', 0)} findings"
        if event_name == "pipeline.llm.skipped":
            return f"[pipeline] llm skipped: {fields.get('reason')}"
        if event_name == "pipeline.adjudication.completed":
            return (
                f"[pipeline] adjudication: risk={fields.get('risk_label')} "
                f"binary={fields.get('binary_label')} score={fields.get('risk_score')}"
            )
        if event_name == "runtime.llm.model.loaded":
            return f"[runtime] llm load: {fields.get('model_id')}"
        if event_name == "runtime.llm.model.reused":
            return f"[runtime] llm reuse: {fields.get('model_id')}"
        if event_name == "runtime.llm.model.evicted":
            return f"[runtime] llm evict: {fields.get('model_id')}"
        if event_name == "runtime.ml.model.loaded":
            return f"[runtime] ml load: {fields.get('model_id')}"
        if event_name == "runtime.ml.model.reused":
            return f"[runtime] ml reuse: {fields.get('model_id')}"
        if event_name == "runtime.repomix.cache_hit":
            return f"[runtime] repomix cache hit: {fields.get('skill_path')}"
        if event_name == "runtime.repomix.cache_miss":
            return f"[runtime] repomix cache miss: {fields.get('skill_path')}"

        return None
