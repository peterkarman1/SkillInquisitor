"""Epic 9 fixture entrypoint for ML regression coverage."""

import pytest


def test_ml_fixtures(load_active_fixture_specs):
    fixtures = load_active_fixture_specs("ml")
    if not fixtures:
        pytest.skip("ML fixtures land in Epic 9")
