from skillinquisitor.models import Artifact, NormalizationTransformation, NormalizationType


def test_artifact_supports_typed_normalization_transformations():
    artifact = Artifact(
        path="SKILL.md",
        raw_content="eval",
        normalization_transformations=[
            NormalizationTransformation(
                transformation_type=NormalizationType.KEYWORD_SPLITTER_COLLAPSE,
                original_snippet="e.v.a.l",
                normalized_snippet="eval",
            )
        ],
    )

    assert artifact.normalization_transformations[0].normalized_snippet == "eval"
