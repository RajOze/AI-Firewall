"""Unit tests for FirewallService."""

import pytest

from app.firewall.models import FirewallAction, FirewallDirection, FirewallRule
from app.firewall.provider import FirewallProvider
from app.firewall.service import FirewallService
from app.firewall.validator import FirewallValidationError


class FakeFirewallProvider(FirewallProvider):
    """Fake provider that records calls for testing."""

    def __init__(self) -> None:
        self.added_rules: list[FirewallRule] = []
        self.removed_names: list[str] = []
        self.existence_checks: dict[str, bool] = {}
        self.existence_check_calls: list[str] = []

    def add_rule(self, rule: FirewallRule) -> None:
        self.added_rules.append(rule)

    def remove_rule(self, name: str) -> None:
        self.removed_names.append(name)

    def rule_exists(self, name: str) -> bool:
        self.existence_check_calls.append(name)
        # Return stored value if present, else False
        return self.existence_checks.get(name, False)


def test_service_rejects_non_provider() -> None:
    """FirewallService should reject non-provider objects."""
    with pytest.raises(TypeError, match="provider must implement FirewallProvider"):
        FirewallService(provider="not a provider")  # type: ignore[arg-type]


def test_add_rule_validates_and_normalizes_before_delegation() -> None:
    """Valid rule should be validated and normalized before calling provider."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    # Rule with extra spaces
    rule = FirewallRule(
        name="  Test Rule  ",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="  192.168.1.0/24  ",
        program=r"C:\Program Files\App\App.exe  ",
        description="  A test rule  ",
    )

    service.add_rule(rule)

    # Provider should have received validated/normalized rule
    assert len(provider.added_rules) == 1
    saved_rule = provider.added_rules[0]
    assert saved_rule.name == "Test Rule"
    assert saved_rule.remote_address == "192.168.1.0/24"
    assert saved_rule.program == r"C:\Program Files\App\App.exe"
    assert saved_rule.description == "A test rule"
    assert saved_rule.action == FirewallAction.ALLOW
    assert saved_rule.direction == FirewallDirection.INBOUND


def test_add_rule_does_not_call_provider_on_validation_error() -> None:
    """If validation fails, provider.add_rule should not be called."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    # Empty name should raise validation error
    bad_rule = FirewallRule(
        name="   ",
        action=FirewallAction.BLOCK,
        direction=FirewallDirection.OUTBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallValidationError, match="Firewall rule name cannot be empty"):
        service.add_rule(bad_rule)

    assert provider.added_rules == []  # provider not called


def test_remove_rule_validates_and_normalizes_before_delegation() -> None:
    """Valid rule name should be validated and normalized before calling provider."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    # Name with extra spaces
    service.remove_rule("  My Rule  ")

    assert provider.removed_names == ["My Rule"]


def test_remove_rule_does_not_call_provider_for_invalid_name() -> None:
    """If name validation fails, provider.remove_rule should not be called."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallValidationError, match="Firewall rule name cannot be empty"):
        service.remove_rule("   ")

    assert provider.removed_names == []


def test_rule_exists_validates_and_normalizes_before_delegation() -> None:
    """rule_exists should validate and normalize name before asking provider."""
    provider = FakeFirewallProvider()
    # Pre-populate existence map
    provider.existence_checks["Existing Rule"] = True
    provider.existence_checks["Another"] = False

    service = FirewallService(provider=provider)

    # Leading/trailing spaces
    assert service.rule_exists("  Existing Rule  ") is True
    assert service.rule_exists("  Another  ") is False

    # Provider should have received normalized names
    assert provider.existence_check_calls == ["Existing Rule", "Another"]


def test_rule_exists_returns_provider_result() -> None:
    """rule_exists should return whatever the provider returns."""
    provider = FakeFirewallProvider()
    provider.existence_checks["Test"] = False
    service = FirewallService(provider=provider)

    assert service.rule_exists("Test") is False

    provider.existence_checks["Test"] = True
    assert service.rule_exists("Test") is True


def test_rule_exists_does_not_call_provider_for_invalid_name() -> None:
    """If name validation fails, provider.rule_exists should not be called."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallValidationError, match="Firewall rule name cannot be empty"):
        service.rule_exists("   ")
    # Ensure provider's existence_check_calls unchanged (no call)
    assert provider.existence_check_calls == []