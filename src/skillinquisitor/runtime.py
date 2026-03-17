from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import TypeVar

from skillinquisitor.models import ScanConfig

T = TypeVar("T")


class ScanRuntime:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._ml_slots = asyncio.Semaphore(max(1, config.runtime.ml_global_slots))
        self._llm_slots = asyncio.Semaphore(max(1, config.runtime.llm_global_slots))

    @classmethod
    def from_config(cls, config: ScanConfig) -> "ScanRuntime":
        return cls(config)

    async def close(self) -> None:
        return None

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
