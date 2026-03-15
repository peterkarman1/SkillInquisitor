"""Epic 11 fixture entrypoint for scoring regression coverage."""

import pytest


def test_scoring_fixtures(load_active_fixture_specs):
    fixtures = load_active_fixture_specs("scoring")
    if not fixtures:
        pytest.skip("Scoring fixtures land in Epic 11")
