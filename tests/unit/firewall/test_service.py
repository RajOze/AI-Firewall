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
from app.firewall.models import (
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    FirewallRuleIdentity,
)
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
        self.added_identities: list[FirewallRuleIdentity] = []
        self.removed_names: list[str] = []
        self.existence_checks: dict[str, bool] = {}
        self.existence_check_calls: list[str] = []
        self.is_admin_result: bool = True
        self.auto_update_existence: bool = True

    def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
        self.added_rules.append(rule)
        identity = FirewallRuleIdentity(
            name=f"AI-Firewall-id-{rule.name}",
            display_name=rule.name,
        )
        self.added_identities.append(identity)
        if self.auto_update_existence:
            self.existence_checks[rule.name] = True
            self.existence_checks[identity.name] = True
        return identity

    def remove_rule(self, identity_or_name: FirewallRuleIdentity | str) -> None:
        key = (
            identity_or_name.name
            if isinstance(identity_or_name, FirewallRuleIdentity)
            else identity_or_name.strip()
        )
        self.removed_names.append(key)
        if self.auto_update_existence:
            self.existence_checks[key] = False
            if isinstance(identity_or_name, FirewallRuleIdentity):
                self.existence_checks[identity_or_name.display_name] = False

    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        key = (
            identity_or_name.name
            if isinstance(identity_or_name, FirewallRuleIdentity)
            else identity_or_name.strip()
        )
        self.existence_check_calls.append(key)
        return self.existence_checks.get(key, False)

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
    """managed_rule should create rule, yield FirewallRuleIdentity, and remove rule upon exit using identity."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="  AI-Firewall-Managed  ",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with service.managed_rule(rule) as identity:
        assert isinstance(identity, FirewallRuleIdentity)
        assert identity.display_name == "AI-Firewall-Managed"
        assert identity.name == "AI-Firewall-id-AI-Firewall-Managed"
        assert len(provider.added_rules) == 1
        assert provider.added_rules[0].name == "AI-Firewall-Managed"
        assert provider.rule_exists(identity) is True

    assert provider.removed_names == ["AI-Firewall-id-AI-Firewall-Managed"]
    assert provider.rule_exists("AI-Firewall-id-AI-Firewall-Managed") is False




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

    assert provider.removed_names == ["AI-Firewall-id-AI-Firewall-CrashTest"]
    assert provider.rule_exists("AI-Firewall-id-AI-Firewall-CrashTest") is False


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


def test_add_rule_returns_firewall_rule_identity() -> None:
    """add_rule should return a FirewallRuleIdentity with unique primary key and display_name."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Identity-Test",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    identity = service.add_rule(rule)

    assert isinstance(identity, FirewallRuleIdentity)
    assert identity.display_name == "AI-Firewall-Identity-Test"
    assert identity.name == "AI-Firewall-id-AI-Firewall-Identity-Test"
    assert service.rule_exists(identity) is True


def test_add_rule_rejects_identity_mismatch() -> None:
    """add_rule should raise FirewallCreationVerificationError if provider returns mismatched display_name."""
    class MismatchedProvider(FakeFirewallProvider):
        def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
            return FirewallRuleIdentity(
                name="AI-Firewall-Substituted",
                display_name="AI-Firewall-Wrong-Name",
            )

    provider = MismatchedProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Original",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCreationVerificationError, match="does not match rule name"):
        service.add_rule(rule)


def test_remove_rule_by_firewall_rule_identity() -> None:
    """remove_rule should accept a FirewallRuleIdentity instance and target primary key."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    identity = FirewallRuleIdentity(
        name="AI-Firewall-id-Target",
        display_name="AI-Firewall-Target",
    )
    provider.existence_checks[identity.name] = True
    provider.existence_checks[identity.display_name] = True

    service.remove_rule(identity)

    assert provider.removed_names == [identity.name]
    assert provider.rule_exists(identity) is False


def test_identity_safety_deterministic_behavior() -> None:
    """Same starting state and request produces identical deterministic outcome."""
    provider1 = FakeFirewallProvider()
    service1 = FirewallService(provider=provider1)

    provider2 = FakeFirewallProvider()
    service2 = FirewallService(provider=provider2)

    rule = FirewallRule(
        name="AI-Firewall-Deterministic",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    id1 = service1.add_rule(rule)
    id2 = service2.add_rule(rule)

    assert id1.name == id2.name
    assert id1.display_name == id2.display_name


def test_no_real_windows_mutation_called() -> None:
    """Fake/mock tests must not call subprocess or real OS mutation cmdlets."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-MockOnly",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    identity = service.add_rule(rule)
    assert isinstance(identity, FirewallRuleIdentity)
    service.remove_rule(identity)

    # 100% in-memory mocked execution; provider.added_rules recorded
    assert len(provider.added_rules) == 1
    assert provider.removed_names == [identity.name]


def test_adversarial_display_name_confusion_preserves_other_rule() -> None:
    """Removing rule 1 by identity must not remove rule 2 even if display names are similar."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule1 = FirewallRule(
        name="AI-Firewall-SharedName",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )
    rule2 = FirewallRule(
        name="AI-Firewall-SharedName-V2",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.2",
    )

    identity1 = service.add_rule(rule1)
    identity2 = service.add_rule(rule2)

    assert identity1.name != identity2.name

    # Remove rule1 only
    service.remove_rule(identity1)

    assert provider.rule_exists(identity1) is False
    assert provider.rule_exists(identity2) is True


def test_adversarial_bare_prefix_namespace_rejected() -> None:
    """Bare prefix 'AI-Firewall-' without a suffix must be rejected as an unsafe namespace."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(UnsafeRuleNamespaceError, match="must include a unique identifier suffix"):
        service.add_rule(rule)


def test_adversarial_malformed_identity_attribute_types_rejected() -> None:
    """Provider returning non-string name or display_name attributes must fail closed."""
    class RogueProvider(FakeFirewallProvider):
        def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
            return FirewallRuleIdentity(
                name=12345,  # type: ignore[arg-type]
                display_name="AI-Firewall-Valid",
            )

    provider = RogueProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Valid",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCreationVerificationError, match="invalid identity attribute types"):
        service.add_rule(rule)


def test_adversarial_invalid_remove_target_type_rejected() -> None:
    """Passing an invalid target type to remove_rule must raise FirewallValidationError."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallValidationError, match="must be a FirewallRuleIdentity or string"):
        service.remove_rule(12345)  # type: ignore[arg-type]


def test_adversarial_invalid_rule_exists_target_type_rejected() -> None:
    """Passing an invalid target type to rule_exists must raise FirewallValidationError."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    with pytest.raises(FirewallValidationError, match="must be a FirewallRuleIdentity or string"):
        service.rule_exists(None)  # type: ignore[arg-type]


def test_phase87_valid_trusted_mutation_reaches_executor_and_verifies() -> None:
    """Valid trusted mutation reaches provider executor and post-mutation verification succeeds."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Phase87-Trusted",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.100",
    )

    identity = service.add_rule(rule)

    assert isinstance(identity, FirewallRuleIdentity)
    assert identity.display_name == "AI-Firewall-Phase87-Trusted"
    assert identity.name == "AI-Firewall-id-AI-Firewall-Phase87-Trusted"
    assert provider.rule_exists(identity.name) is True
    assert len(provider.added_rules) == 1


def test_phase87_unvalidated_raw_input_cannot_reach_executor() -> None:
    """Raw input with invalid IP address cannot reach provider executor."""
    provider = FakeFirewallProvider()
    service = FirewallService(provider=provider)

    invalid_rule = FirewallRule(
        name="AI-Firewall-InvalidIP",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="invalid-ip-address",
    )

    with pytest.raises(FirewallValidationError, match="valid IPv4/IPv6 address"):
        service.add_rule(invalid_rule)

    assert provider.added_rules == []


def test_phase87_execution_failure_raises_error_without_reporting_success() -> None:
    """OS/subprocess execution error in provider raises error and does not verify or report success."""
    from app.firewall.windows_provider import WindowsFirewallProviderError

    class FailingProvider(FakeFirewallProvider):
        def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
            raise WindowsFirewallProviderError("PowerShell command failed")

    provider = FailingProvider()
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-FailingOS",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(WindowsFirewallProviderError, match="PowerShell command failed"):
        service.add_rule(rule)


def test_phase87_post_mutation_verification_failure_raises_creation_error() -> None:
    """Post-mutation state verification failure raises FirewallCreationVerificationError."""
    provider = FakeFirewallProvider()
    provider.auto_update_existence = False  # provider does not update existence_checks
    service = FirewallService(provider=provider)

    rule = FirewallRule(
        name="AI-Firewall-Unverifiable",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="10.0.0.1",
    )

    with pytest.raises(FirewallCreationVerificationError, match="Post-creation verification failed"):
        service.add_rule(rule)

    assert len(provider.added_rules) == 1