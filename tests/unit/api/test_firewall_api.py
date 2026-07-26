"""Unit tests for Firewall API endpoints and safe read-only dependency wiring."""

import pytest
from fastapi.testclient import TestClient

from app.dependencies.firewall import get_firewall_service
from app.firewall.models import FirewallRule, FirewallRuleIdentity
from app.firewall.provider import FirewallProvider
from app.firewall.service import FirewallService
from app.main import app


class MutationFailingProvider(FirewallProvider):
    """Fake FirewallProvider that raises AssertionError if any mutation method is called."""

    def __init__(self, exists_map: dict[str, bool] | None = None):
        self._exists_map = exists_map or {}

    def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
        raise AssertionError("Mutation path 'add_rule' invoked during read-only operation!")

    def remove_rule(self, identity_or_name: FirewallRuleIdentity | str) -> None:
        raise AssertionError("Mutation path 'remove_rule' invoked during read-only operation!")

    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        name_key = (
            identity_or_name.name
            if isinstance(identity_or_name, FirewallRuleIdentity)
            else identity_or_name
        )
        return self._exists_map.get(name_key, False)

    def is_administrator(self) -> bool:
        return True


@pytest.fixture
def client():
    """TestClient fixture with auto-cleared dependency overrides."""
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_firewall_router_is_registered(client):
    """Verify GET /firewall/rules/{rule_name} route is registered in the application."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-test": False})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-test")
    assert response.status_code == 200


def test_endpoint_returns_expected_response_when_rule_exists(client):
    """Verify endpoint returns exists=True when service reports rule exists."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-rule1": True})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-rule1")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-rule1",
        "exists": True,
    }


def test_endpoint_returns_expected_response_when_rule_absent(client):
    """Verify endpoint returns exists=False when service reports rule absent."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-rule1": False})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-rule1")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-rule1",
        "exists": False,
    }


def test_dependency_override_is_honored(client):
    """Verify FastAPI dependency override for get_firewall_service is dynamically honored."""
    service_a = FirewallService(provider=MutationFailingProvider(exists_map={"ruleX": True}))
    service_b = FirewallService(provider=MutationFailingProvider(exists_map={"ruleX": False}))

    app.dependency_overrides[get_firewall_service] = lambda: service_a
    res1 = client.get("/firewall/rules/ruleX")
    assert res1.json()["exists"] is True

    app.dependency_overrides[get_firewall_service] = lambda: service_b
    res2 = client.get("/firewall/rules/ruleX")
    assert res2.json()["exists"] is False


def test_invalid_rule_name_validation_error_mapped_to_400(client):
    """Verify empty/spaces-only or malformed rule name raises 400 Bad Request."""
    provider = MutationFailingProvider()
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    # Rule name exceeding max length (128 chars)
    long_rule_name = "A" * 130
    response = client.get(f"/firewall/rules/{long_rule_name}")
    assert response.status_code == 400
    assert "exceeds 128 characters" in response.json()["detail"]


def test_existing_health_endpoint_remains_intact(client):
    """Verify GET /health remains intact and returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_existing_analyze_endpoint_remains_intact(client):
    """Verify POST /analyze/ remains intact and functions for detection."""
    response = client.post("/analyze/", json={"text": "Hello world"})
    assert response.status_code == 200
    data = response.json()
    assert "safe" in data
    assert "score" in data
    assert "category" in data
    assert "reason" in data


def test_mutation_safety_guard_prevents_any_mutation_invocation(client):
    """Explicit mutation safety test: provider mutation methods fail immediately if called.

    Endpoint execution must succeed without calling add_rule or remove_rule.
    """
    provider = MutationFailingProvider(exists_map={"AI-Firewall-safe-rule": True})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-safe-rule")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-safe-rule",
        "exists": True,
    }
