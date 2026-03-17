from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
import threading
import time
from typing import TypeVar

from skillinquisitor.detectors.llm.download import _expand_cache_dir, resolve_model_file
from skillinquisitor.detectors.llm.models import (
    CodeAnalysisModel,
    build_code_analysis_model,
    detect_hardware_profile,
    resolve_group_models,
)
from skillinquisitor.detectors.ml.models import InjectionModel, build_injection_model
from skillinquisitor.models import ScanConfig

T = TypeVar("T")


@dataclass
class RuntimeTelemetry:
    llm_cold_loads: int = 0
    llm_warm_reuses: int = 0
    llm_evictions: int = 0
    ml_cold_loads: int = 0
    ml_warm_reuses: int = 0
    repomix_cache_hits: int = 0
    repomix_cache_misses: int = 0

    def as_dict(self, config: ScanConfig) -> dict[str, object]:
        return {
            "scan_workers": config.runtime.scan_workers,
            "ml_global_slots": config.runtime.ml_global_slots,
            "llm_global_slots": config.runtime.llm_global_slots,
            "ml_lifecycle": config.runtime.ml_lifecycle,
            "llm_lifecycle": config.runtime.llm_lifecycle,
            "llm_cold_loads": self.llm_cold_loads,
            "llm_warm_reuses": self.llm_warm_reuses,
            "llm_evictions": self.llm_evictions,
            "ml_cold_loads": self.ml_cold_loads,
            "ml_warm_reuses": self.ml_warm_reuses,
            "repomix_cache_hits": self.repomix_cache_hits,
            "repomix_cache_misses": self.repomix_cache_misses,
        }


@dataclass
class _LLMPoolEntry:
    key: tuple[object, ...]
    model: CodeAnalysisModel
    request_slots: threading.Semaphore
    last_used: float = field(default_factory=time.monotonic)
    in_use: int = 0


class _PooledCodeAnalysisModel:
    def __init__(self, entry: _LLMPoolEntry) -> None:
        self.model_id = entry.model.model_id
        self._entry = entry

    def load(self) -> None:
        return None

    def generate_structured(self, prompt: str, max_tokens: int) -> dict[str, object]:
        self._entry.request_slots.acquire()
        try:
            self._entry.last_used = time.monotonic()
            return self._entry.model.generate_structured(prompt, max_tokens)
        finally:
            self._entry.request_slots.release()

    def unload(self) -> None:
        return None


@dataclass
class _MLPoolEntry:
    model: InjectionModel
    lock: threading.Lock = field(default_factory=threading.Lock)


class _PooledInjectionModel:
    def __init__(self, entry: _MLPoolEntry) -> None:
        self.model_id = entry.model.model_id
        self._entry = entry

    def load(self) -> None:
        return None

    def predict_many(self, texts: list[str], batch_size: int):
        with self._entry.lock:
            return self._entry.model.predict_many(texts, batch_size=batch_size)

    def unload(self) -> None:
        return None


@dataclass
class LLMLease:
    group_name: str
    models: list[CodeAnalysisModel]
    failed_models: list[dict[str, object]]
    _release: Callable[[], None] | None = None

    def release(self) -> None:
        if self._release is not None:
            self._release()
            self._release = None


class ScanRuntime:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._ml_slots = asyncio.Semaphore(max(1, config.runtime.ml_global_slots))
        self._llm_slots = asyncio.Semaphore(max(1, config.runtime.llm_global_slots))
        self._llm_lock = threading.Lock()
        self._ml_lock = threading.Lock()
        self._repomix_lock = threading.Lock()
        self._llm_pool: dict[tuple[object, ...], _LLMPoolEntry] = {}
        self._ml_pool: dict[str, _MLPoolEntry] = {}
        self._repomix_cache: dict[tuple[str, tuple[str, ...], str], str | None] = {}
        self._telemetry = RuntimeTelemetry()

    @classmethod
    def from_config(cls, config: ScanConfig) -> "ScanRuntime":
        return cls(config)

    async def close(self) -> None:
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        with self._llm_lock:
            entries = list(self._llm_pool.values())
            self._llm_pool.clear()
        for entry in entries:
            entry.model.unload()
        with self._ml_lock:
            ml_entries = list(self._ml_pool.values())
            self._ml_pool.clear()
        for entry in ml_entries:
            entry.model.unload()

    @asynccontextmanager
    async def ml_section(self):
        async with self._ml_slots:
            yield

    @asynccontextmanager
    async def llm_section(self):
        async with self._llm_slots:
            yield

    async def to_thread(self, func: Callable[..., T], /, *args, **kwargs) -> T:
        return await asyncio.to_thread(func, *args, **kwargs)

    def lease_llm_models(
        self,
        config: ScanConfig,
        *,
        requested_group: str | None = None,
    ) -> LLMLease:
        hardware = detect_hardware_profile(config.layers.llm.device_policy or config.device)
        group_name, model_configs = resolve_group_models(config, requested_group=requested_group, hardware=hardware)
        failed_models: list[dict[str, object]] = []
        pooled_models: list[CodeAnalysisModel] = []
        cache_dir = _expand_cache_dir(config)
        cache_dir.mkdir(parents=True, exist_ok=True)

        with self._llm_lock:
            leased_entries: list[_LLMPoolEntry] = []
            for model_config in model_configs:
                try:
                    key = (
                        model_config.runtime.lower(),
                        model_config.id,
                        model_config.filename,
                        model_config.context_window,
                        hardware.accelerator,
                    )
                    entry = self._llm_pool.get(key)
                    if entry is None:
                        self._evict_llm_entries_if_needed(config)
                        model_path = None
                        if model_config.runtime.lower() != "heuristic":
                            model_path = resolve_model_file(
                                model_config,
                                cache_dir=cache_dir,
                                auto_download=config.layers.llm.auto_download,
                            )
                        model = build_code_analysis_model(
                            model=model_config,
                            model_path=model_path,
                            hardware=hardware,
                            parallel_requests=max(1, config.runtime.llm_server_parallel_requests),
                            server_threads=max(1, config.runtime.llm_server_threads),
                        )
                        model.load()
                        self._telemetry.llm_cold_loads += 1
                        entry = _LLMPoolEntry(
                            key=key,
                            model=model,
                            request_slots=threading.Semaphore(max(1, config.runtime.llm_server_parallel_requests)),
                        )
                        self._llm_pool[key] = entry
                    else:
                        self._telemetry.llm_warm_reuses += 1
                    entry.in_use += 1
                    entry.last_used = time.monotonic()
                    leased_entries.append(entry)
                    pooled_models.append(_PooledCodeAnalysisModel(entry))
                except Exception as exc:  # pragma: no cover - runtime variability
                    failed_models.append({"model_id": model_config.id, "error": type(exc).__name__})

        def release() -> None:
            with self._llm_lock:
                for entry in leased_entries:
                    entry.in_use = max(0, entry.in_use - 1)
                    entry.last_used = time.monotonic()

        return LLMLease(
            group_name=group_name,
            models=pooled_models,
            failed_models=failed_models,
            _release=release,
        )

    def _evict_llm_entries_if_needed(self, config: ScanConfig) -> None:
        limit = max(1, config.runtime.llm_resident_model_limit)
        if len(self._llm_pool) < limit:
            return
        evictable = [entry for entry in self._llm_pool.values() if entry.in_use == 0]
        if not evictable:
            return
        victim = min(evictable, key=lambda entry: entry.last_used)
        victim.model.unload()
        self._telemetry.llm_evictions += 1
        self._llm_pool.pop(victim.key, None)

    def get_ml_models(self, config: ScanConfig) -> list[InjectionModel]:
        cache_dir = Path(config.model_cache_dir).expanduser()
        with self._ml_lock:
            pooled: list[InjectionModel] = []
            for model_config in config.layers.ml.models:
                entry = self._ml_pool.get(model_config.id)
                if entry is None:
                    model = build_injection_model(
                        model_id=model_config.id,
                        model_type=model_config.type,
                        cache_dir=cache_dir,
                        device_preference=config.device,
                        auto_download=config.layers.ml.auto_download,
                    )
                    model.load()
                    self._telemetry.ml_cold_loads += 1
                    entry = _MLPoolEntry(model=model)
                    self._ml_pool[model_config.id] = entry
                else:
                    self._telemetry.ml_warm_reuses += 1
                pooled.append(_PooledInjectionModel(entry))
            return pooled

    def get_repomix_output(
        self,
        *,
        skill_path: str,
        command: str,
        args: list[str],
        runner: Callable[[str], str | None],
    ) -> str | None:
        key = (skill_path, tuple(args), command)
        with self._repomix_lock:
            if key in self._repomix_cache:
                self._telemetry.repomix_cache_hits += 1
                return self._repomix_cache[key]
        output = runner(skill_path)
        with self._repomix_lock:
            self._telemetry.repomix_cache_misses += 1
            self._repomix_cache[key] = output
        return output

    def snapshot(self) -> dict[str, object]:
        return self._telemetry.as_dict(self.config)
