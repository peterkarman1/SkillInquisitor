"""Tests for LLM multi-model consensus on soft findings."""
from __future__ import annotations

from skillinquisitor.detectors.llm.judge import evaluate_soft_consensus


class TestEvaluateSoftConsensus:
    def test_all_confirm(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "confirm"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_three_of_four_confirm(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_two_of_four_reject(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "dispute"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_all_dispute(self):
        responses = [{"disposition": "dispute"}] * 4
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_empty_responses(self):
        assert evaluate_soft_consensus([], threshold=0.75) == "rejected"

    def test_case_insensitive_confirm(self):
        responses = [
            {"disposition": "Confirm"},
            {"disposition": "CONFIRM"},
            {"disposition": "confirmed"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_custom_threshold_50_percent(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.5) == "confirmed"

    def test_custom_threshold_75_percent_fails(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_single_model_confirm(self):
        responses = [{"disposition": "confirm"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_single_model_dispute(self):
        responses = [{"disposition": "dispute"}]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_missing_disposition_counts_as_not_confirm(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"other_key": "value"},  # Missing disposition
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_informational_counts_as_not_confirm(self):
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "informational"},
            {"disposition": "escalate"},
        ]
        # Only 2/4 confirm = 50%, below 75% threshold
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"

    def test_exact_threshold_boundary(self):
        # 3/4 = 0.75, exactly at threshold
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "confirmed"

    def test_just_below_threshold(self):
        # 2/3 = 0.667, below 0.75
        responses = [
            {"disposition": "confirm"},
            {"disposition": "confirm"},
            {"disposition": "dispute"},
        ]
        assert evaluate_soft_consensus(responses, threshold=0.75) == "rejected"
