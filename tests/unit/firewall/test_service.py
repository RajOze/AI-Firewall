"""Unit tests for FirewallService."""

import pytest

from app.firewall.exceptions import (
    FirewallCleanupError,
    FirewallCollisionError,
    FirewallCreationVerificationError,
    FirewallPrivilegeError,
    FirewallRemovalVerificationError,
    FirewallRuleNotFoundError,
)
from app.firewall.models import FirewallAction, FirewallDirection, FirewallRule
from app.firewall.provider import FirewallProvider
from app.firewall.service import FirewallService
from app.firewall.validator import (
    FirewallValidationError,
    UnsafeRuleNamespaceError,
)



class FakeFirewallProvider(FirewallProvider):
    """Fake provider that records calls for testing."""

    def __init__(self) -> None:
        self.added_rules: list[FirewallRule] = []
        self.removed_names: list[str] = []
        self.existence_checks: dict[str, bool] = {}
        self.existence_check_calls: list[str] = []
        self.is_admin_result: bool = True
        self.auto_update_existence: bool = True

    def add_rule(self, rule: FirewallRule) -> None:
        self.added_rules.append(rule)
        if self.auto_update_existence:
            self.existence_checks[rule.name] = True

    def remove_rule(self, name: str) -> None:
        self.removed_names.append(name)
        if self.auto_update_existence:
            self.existence_checks[name] = False

    def rule_exists(self, name: str) -> bool:
        self.existence_check_calls.append(name)
        return self.existence_checks.get(name, False)

    def is_administrator(self) -> bool:
        return self.is_admin_result


def test_service_rejects_non_provider() -> None:
    """FirewallService should reject non-provider objects."""
    with pytest.raises(TypeError, match="provider must implement FirewallProvider"):
        FirewallService(provider="not a provider")  # type: ignore[arg-type]


def test_add_rule_validates_and_normalizes_before_delegation() -> None:
    """Valid rule should be validated and normalized before calling provider."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="  AI-Firewall-Test-Rule  ",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="  192.168.1.0/24  ",
        program=r"C:\Program Files\App\App.exe  ",
        description="  A test rule  ",
    )

    service.add_rule(rule)

    assert len(provider.added_rules) == 1
    saved_rule = provider.added_rules[0]
    assert saved_rule.name == "AI-Firewall-Test-Rule"
    assert saved_rule.remote_address == "192.168.1.0/24"
    assert saved_rule.program == r"C:\Program Files\App\App.exe"
    assert saved_rule.description == "A test rule"
    assert saved_rule.action == FirewallAction.ALLOW
    assert saved_rule.direction == FirewallDirection.INBOUND


def test_add_rule_does_not_call_provider_on_validation_error() -> None:
    """If validation fails, provider.add_rule should not be called."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    bad_rule = FirewallRule(
        name="   ",
        action=FirewallAction.BLOCK,
        direction=FirewallDirection.OUTBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallValidationError, match="Firewall rule name cannot be empty"):
        service.add_rule(bad_rule)

    assert provider.added_rules == []


def test_add_rule_enforces_ai_firewall_prefix_namespace() -> None:
    """add_rule should reject rule names outside AI-Firewall-* namespace."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="CustomRuleName",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(UnsafeRuleNamespaceError, match="must start with required prefix 'AI-Firewall-'"):
        service.add_rule(rule)

    assert provider.added_rules == []


def test_add_rule_rejects_wildcard_characters() -> None:
    """add_rule should reject rule names containing wildcard characters."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Rule*",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(UnsafeRuleNamespaceError, match="cannot contain wildcard characters"):
        service.add_rule(rule)

    assert provider.added_rules == []


def test_add_rule_checks_administrator_preflight() -> None:
    """add_rule should raise FirewallPrivilegeError if not running as administrator."""
    provider = FakeFirewallProvider()
    provider.is_admin_result = False
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-AdminTest",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallPrivilegeError, match="Administrator privileges required"):
        service.add_rule(rule)

    assert provider.added_rules == []


def test_add_rule_detects_collision() -> None:
    """add_rule should raise FirewallCollisionError if rule already exists."""
    provider = FakeFirewallProvider()
    provider.existence_checks["AI-Firewall-Dup"] = True
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Dup",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCollisionError, match="already exists"):
        service.add_rule(rule)

    assert provider.added_rules == []


def test_add_rule_post_creation_verification_failure_raises_error_without_removal() -> None:
    """add_rule should raise FirewallCreationVerificationError if rule_exists returns False after add_rule, without calling remove_rule."""
    provider = FakeFirewallProvider()
    provider.auto_update_existence = False  # existence_checks remains False
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Ghost",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCreationVerificationError, match="Post-creation verification failed"):
        service.add_rule(rule)

    assert len(provider.added_rules) == 1
    assert provider.removed_names == []  # Crucial: NO automatic rollback removal attempted!


def test_remove_rule_enforces_ai_firewall_prefix_namespace() -> None:
    """remove_rule should reject rule names outside AI-Firewall-* namespace."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    with pytest.raises(UnsafeRuleNamespaceError, match="must start with required prefix 'AI-Firewall-'"):
        service.remove_rule("Windows Defender")

    assert provider.removed_names == []


def test_remove_rule_checks_administrator_preflight() -> None:
    """remove_rule should raise FirewallPrivilegeError if not running as administrator."""
    provider = FakeFirewallProvider()
    provider.is_admin_result = False
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallPrivilegeError, match="Administrator privileges required"):
        service.remove_rule("AI-Firewall-Test")

    assert provider.removed_names == []


def test_remove_rule_pre_removal_existence_check_fails() -> None:
    """remove_rule should raise FirewallRuleNotFoundError and NOT call provider.remove_rule if rule is absent."""
    provider = FakeFirewallProvider()
    provider.existence_checks["AI-Firewall-Missing"] = False
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallRuleNotFoundError, match="does not exist"):
        service.remove_rule("AI-Firewall-Missing")

    assert provider.removed_names == []  # provider.remove_rule NOT called!


def test_remove_rule_post_removal_verification_success() -> None:
    """remove_rule should succeed when pre-check passes, remove_rule is called, and post-verification passes."""
    provider = FakeFirewallProvider()
    provider.existence_checks["AI-Firewall-Rule"] = True
    service = FirewallService(provider=provider)

    service.remove_rule("  AI-Firewall-Rule  ")

    assert provider.removed_names == ["AI-Firewall-Rule"]
    assert provider.rule_exists("AI-Firewall-Rule") is False


def test_remove_rule_post_removal_verification_failure() -> None:
    """remove_rule should raise FirewallRemovalVerificationError if rule_exists remains True after removal."""
    provider = FakeFirewallProvider()
    provider.existence_checks["AI-Firewall-Stubborn"] = True
    provider.auto_update_existence = False  # rule_exists remains True after remove_rule call
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallRemovalVerificationError, match="Post-removal verification failed"):
        service.remove_rule("AI-Firewall-Stubborn")

    assert provider.removed_names == ["AI-Firewall-Stubborn"]


def test_rule_exists_validates_and_normalizes_before_delegation() -> None:
    """rule_exists should validate and normalize name before asking provider."""
    provider = FakeFirewallProvider()
    provider.existence_checks["Existing Rule"] = True

    service = FirewallService(provider=provider)

    assert service.rule_exists("  Existing Rule  ") is True
    assert provider.existence_check_calls == ["Existing Rule"]


def test_managed_rule_lifecycle_success() -> None:
    """managed_rule should create rule with canonical name, yield canonical name, and remove rule upon exit using canonical name."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="  AI-Firewall-Managed  ",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with service.managed_rule(rule) as name:
        assert name == "AI-Firewall-Managed"
        assert len(provider.added_rules) == 1
        assert provider.added_rules[0].name == "AI-Firewall-Managed"
        assert provider.rule_exists("AI-Firewall-Managed") is True

    assert provider.removed_names == ["AI-Firewall-Managed"]
    assert provider.rule_exists("AI-Firewall-Managed") is False



def test_managed_rule_lifecycle_does_not_attempt_cleanup_if_add_rule_fails() -> None:
    """managed_rule should NOT attempt cleanup removal if add_rule fails during pre-checks or creation."""
    provider = FakeFirewallProvider()
    provider.existence_checks["AI-Firewall-Dup"] = True  # Trigger collision error in add_rule
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Dup",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCollisionError):
        with service.managed_rule(rule):
            pass

    assert provider.removed_names == []  # Cleanup never attempted because add_rule failed!


def test_managed_rule_lifecycle_cleans_up_on_inner_exception() -> None:
    """managed_rule should clean up rule if an exception occurs inside the with block, and propagate original exception."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-CrashTest",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    class CustomTestException(Exception):
        pass

    with pytest.raises(CustomTestException, match="Inner test failure"):
        with service.managed_rule(rule):
            raise CustomTestException("Inner test failure")

    assert provider.removed_names == ["AI-Firewall-CrashTest"]
    assert provider.rule_exists("AI-Firewall-CrashTest") is False


def test_managed_rule_lifecycle_surfaces_cleanup_failure() -> None:
    """managed_rule should raise FirewallCleanupError if cleanup removal fails during teardown."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-CleanupFail",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    # Force remove_rule to fail by making is_administrator return False right before cleanup
    with pytest.raises(FirewallCleanupError, match="Failed to cleanup firewall rule"):
        with service.managed_rule(rule):
            provider.is_admin_result = False  # preflight check in remove_rule will fail