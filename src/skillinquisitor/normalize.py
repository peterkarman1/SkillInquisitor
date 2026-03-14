from __future__ import annotations

from skillinquisitor.models import Artifact, Location, ProvenanceStep, Segment, SegmentType


def normalize_artifact(artifact: Artifact) -> Artifact:
    location = Location(file_path=artifact.path)
    segment = Segment(
        content=artifact.raw_content,
        segment_type=SegmentType.ORIGINAL,
        location=location,
        provenance_chain=[
            ProvenanceStep(
                segment_type=SegmentType.ORIGINAL,
                source_location=location,
                description="Original artifact content",
            )
        ],
    )
    return artifact.model_copy(
        update={
            "normalized_content": artifact.raw_content,
            "segments": [segment],
        }
    )
