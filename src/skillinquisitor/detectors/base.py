from __future__ import annotations

from typing import Protocol

from skillinquisitor.models import Finding, ScanConfig, Segment


class SegmentDetector(Protocol):
    def detect(self, segment: Segment, config: ScanConfig) -> list[Finding]:
        """Return findings for a single segment."""


class BatchDetector(Protocol):
    async def detect_batch(
        self,
        segments: list[Segment],
        config: ScanConfig,
        prior_findings: list[Finding] | None = None,
    ) -> list[Finding]:
        """Return findings for a batch of segments."""
