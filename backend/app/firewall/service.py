from contextlib import contextmanager

from app.firewall.exceptions import (
    FirewallCleanupError,
    FirewallCollisionError,
    FirewallCreationVerificationError,
    FirewallPrivilegeError,
    FirewallRemovalVerificationError,
    FirewallRuleNotFoundError,
)
from app.firewall.models import FirewallRule, FirewallRuleIdentity
from app.firewall.provider import FirewallProvider
from app.firewall.validator import (
    REQUIRED_RULE_PREFIX,
    FirewallValidationError,
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

    def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
        """Validate, authorize, preflight, check collision, create, and verify firewall rule identity."""
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

        identity = self._provider.add_rule(validated_rule)
        if not isinstance(identity, FirewallRuleIdentity):
            raise FirewallCreationVerificationError(
                f"Provider failed to return a valid FirewallRuleIdentity for '{validated_rule.name}'."
            )

        if not isinstance(identity.name, str) or not isinstance(identity.display_name, str):
            raise FirewallCreationVerificationError(
                f"Provider returned invalid identity attribute types for '{validated_rule.name}'."
            )

        validate_firewall_rule_namespace(identity.display_name)
        canonical_primary_name = validate_firewall_rule_namespace(identity.name)

        if identity.display_name != validated_rule.name:
            raise FirewallCreationVerificationError(
                f"Identity display_name '{identity.display_name}' does not match rule name '{validated_rule.name}'."
            )

        if not self._provider.rule_exists(canonical_primary_name):
            raise FirewallCreationVerificationError(
                f"Post-creation verification failed: Rule with identity '{canonical_primary_name}' was not found after creation."
            )

        return identity

    def remove_rule(self, identity_or_name: FirewallRuleIdentity | str) -> None:
        """Validate, authorize, preflight, check existence, remove, and verify firewall rule absence."""
        if not self._provider.is_administrator():
            raise FirewallPrivilegeError(
                "Administrator privileges required for firewall mutation."
            )

        if isinstance(identity_or_name, FirewallRuleIdentity):
            if not isinstance(identity_or_name.name, str) or not isinstance(identity_or_name.display_name, str):
                raise FirewallValidationError("FirewallRuleIdentity fields must be strings.")
            validate_firewall_rule_namespace(identity_or_name.display_name)
            key = validate_firewall_rule_namespace(identity_or_name.name)
        elif isinstance(identity_or_name, str):
            validated_name = validate_firewall_rule_name(identity_or_name)
            key = validate_firewall_rule_namespace(validated_name)
        else:
            raise FirewallValidationError(
                "remove_rule target must be a FirewallRuleIdentity or string."
            )

        if not self._provider.rule_exists(key):
            raise FirewallRuleNotFoundError(
                f"Firewall rule '{key}' does not exist."
            )

        self._provider.remove_rule(identity_or_name)

        if self._provider.rule_exists(key):
            raise FirewallRemovalVerificationError(
                f"Post-removal verification failed: Rule '{key}' still exists after removal."
            )

    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        """Validate the rule identity/name and query the configured provider."""
        if isinstance(identity_or_name, FirewallRuleIdentity):
            if not isinstance(identity_or_name.name, str):
                raise FirewallValidationError("FirewallRuleIdentity name must be a string.")
            key = validate_firewall_rule_namespace(identity_or_name.name)
            return self._provider.rule_exists(key)

        if isinstance(identity_or_name, str):
            validated_name = validate_firewall_rule_name(identity_or_name)
            return self._provider.rule_exists(validated_name)

        raise FirewallValidationError(
            "rule_exists target must be a FirewallRuleIdentity or string."
        )

    @contextmanager
    def managed_rule(self, rule: FirewallRule):
        """Context manager guaranteeing creation, verification, and teardown cleanup after successful addition."""
        identity = self.add_rule(rule)
        try:
            yield identity
        finally:
            try:
                self.remove_rule(identity)
            except Exception as cleanup_exc:
                raise FirewallCleanupError(
                    f"Failed to cleanup firewall rule '{identity.name}': {cleanup_exc}"
                ) from cleanup_exc
