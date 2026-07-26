from contextlib import contextmanager

from app.firewall.exceptions import (
    FirewallCleanupError,
    FirewallCollisionError,
    FirewallCreationVerificationError,
    FirewallPrivilegeError,
    FirewallRemovalVerificationError,
    FirewallRuleNotFoundError,
)
from app.firewall.models import FirewallRule
from app.firewall.provider import FirewallProvider
from app.firewall.validator import (
    validate_firewall_rule,
    validate_firewall_rule_name,
    validate_firewall_rule_namespace,
)


class FirewallService:
    """
    Orchestrates firewall operations through validation and a provider.

    Callers must use this service rather than invoking a firewall provider
    directly. Operating-system-specific behavior belongs in provider
    implementations, not here.
    """

    def __init__(self, provider: FirewallProvider) -> None:
        if not isinstance(provider, FirewallProvider):
            raise TypeError("provider must implement FirewallProvider.")

        self._provider = provider

    def add_rule(self, rule: FirewallRule) -> None:
        """Validate, authorize, preflight, check collision, create, and verify firewall rule."""
        validated_rule = validate_firewall_rule(rule)
        validate_firewall_rule_namespace(validated_rule.name)

        if not self._provider.is_administrator():
            raise FirewallPrivilegeError(
                "Administrator privileges required for firewall mutation."
            )

        if self._provider.rule_exists(validated_rule.name):
            raise FirewallCollisionError(
                f"Firewall rule '{validated_rule.name}' already exists."
            )

        self._provider.add_rule(validated_rule)

        if not self._provider.rule_exists(validated_rule.name):
            raise FirewallCreationVerificationError(
                f"Post-creation verification failed: Rule '{validated_rule.name}' was not found after creation."
            )

    def remove_rule(self, name: str) -> None:
        """Validate, authorize, preflight, check existence, remove, and verify firewall rule absence."""
        validated_name = validate_firewall_rule_name(name)
        validate_firewall_rule_namespace(validated_name)

        if not self._provider.is_administrator():
            raise FirewallPrivilegeError(
                "Administrator privileges required for firewall mutation."
            )

        if not self._provider.rule_exists(validated_name):
            raise FirewallRuleNotFoundError(
                f"Firewall rule '{validated_name}' does not exist."
            )

        self._provider.remove_rule(validated_name)

        if self._provider.rule_exists(validated_name):
            raise FirewallRemovalVerificationError(
                f"Post-removal verification failed: Rule '{validated_name}' still exists after removal."
            )

    def rule_exists(self, name: str) -> bool:
        """Validate the rule name and query the configured provider."""
        validated_name = validate_firewall_rule_name(name)
        return self._provider.rule_exists(validated_name)

    @contextmanager
    def managed_rule(self, rule: FirewallRule):
        """Context manager guaranteeing creation, verification, and teardown cleanup after successful addition."""
        validated_rule = validate_firewall_rule(rule)
        self.add_rule(validated_rule)
        canonical_name = validated_rule.name
        try:
            yield canonical_name
        finally:
            try:
                self.remove_rule(canonical_name)
            except Exception as cleanup_exc:
                raise FirewallCleanupError(
                    f"Failed to cleanup firewall rule '{canonical_name}': {cleanup_exc}"
                ) from cleanup_exc
