"""Unit tests for Firewall API boundary hardening and safe read-only dependency wiring."""

import pytest
from fastapi.testclient import TestClient

from app.dependencies.firewall import get_firewall_service
from app.firewall.models import FirewallRule, FirewallRuleIdentity
from app.firewall.provider import FirewallProvider
from app.firewall.service import FirewallService
from app.firewall.windows_provider import WindowsFirewallProviderError
from app.main import app


class MutationFailingProvider(FirewallProvider):
    """Fake FirewallProvider that tracks queries and fails immediately if mutated."""

    def __init__(self, exists_map: dict[str, bool] | None = None):
        self._exists_map = exists_map or {}
        self.rule_exists_call_count = 0

    def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
        raise AssertionError("Mutation path 'add_rule' invoked during read-only operation!")

    def remove_rule(self, identity_or_name: FirewallRuleIdentity | str) -> None:
        raise AssertionError("Mutation path 'remove_rule' invoked during read-only operation!")

    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        self.rule_exists_call_count += 1
        name_key = (
            identity_or_name.name
            if isinstance(identity_or_name, FirewallRuleIdentity)
            else identity_or_name
        )
        return self._exists_map.get(name_key, False)

    def is_administrator(self) -> bool:
        return True


class QueryFailingProvider(MutationFailingProvider):
    """Fake FirewallProvider whose rule_exists raises a sensitive internal error."""

    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        self.rule_exists_call_count += 1
        raise WindowsFirewallProviderError(
            "SENSITIVE_INTERNAL_POWERSHELL_DETAIL: Failed execution at line 42 with exit code 2"
        )


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


def test_valid_existing_identity_returns_200(client):
    """Verify endpoint returns exists=True when rule exists."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-rule1": True})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-rule1")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-rule1",
        "exists": True,
    }


def test_valid_absent_identity_returns_200(client):
    """Verify endpoint returns exists=False when rule is absent."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-rule1": False})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-rule1")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-rule1",
        "exists": False,
    }


def test_invalid_identity_fails_validation_before_provider_query(client):
    """Verify domain validation occurs BEFORE provider query is called."""
    provider = MutationFailingProvider()
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    # Rule name exceeding max length (128 chars)
    long_rule_name = "A" * 130
    response = client.get(f"/firewall/rules/{long_rule_name}")
    assert response.status_code == 400
    assert "exceeds 128 characters" in response.json()["detail"]
    # Explicit proof: provider rule_exists was NEVER called
    assert provider.rule_exists_call_count == 0


def test_provider_query_failure_does_not_leak_internal_details(client):
    """Verify provider query failure returns 500 and does NOT leak internal/PowerShell details."""
    provider = QueryFailingProvider()
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-test")
    assert response.status_code == 500
    response_text = response.text
    assert "SENSITIVE_INTERNAL_POWERSHELL_DETAIL" not in response_text
    assert response.json() == {"detail": "Firewall query operation failed."}


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


def test_mutation_trap_prevents_any_mutation_invocation(client):
    """Explicit mutation safety test: provider mutation methods fail immediately if called."""
    provider = MutationFailingProvider(exists_map={"AI-Firewall-safe-rule": True})
    service = FirewallService(provider=provider)
    app.dependency_overrides[get_firewall_service] = lambda: service

    response = client.get("/firewall/rules/AI-Firewall-safe-rule")
    assert response.status_code == 200
    assert response.json() == {
        "rule_name": "AI-Firewall-safe-rule",
        "exists": True,
    }


def test_direct_provider_isolation_in_api_module():
    """Verify API module does not import or instantiate WindowsFirewallProvider."""
    import app.api.firewall as firewall_api_module

    module_content = open(firewall_api_module.__file__, "r", encoding="utf-8").read()
    assert "WindowsFirewallProvider" not in module_content
    assert "windows_provider" not in module_content


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
