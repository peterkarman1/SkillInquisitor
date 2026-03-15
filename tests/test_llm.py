"""Epic 10 fixture entrypoint for LLM regression coverage."""

import pytest


def test_llm_fixtures(load_active_fixture_specs):
    fixtures = load_active_fixture_specs("llm")
    if not fixtures:
        pytest.skip("LLM fixtures land in Epic 10")
