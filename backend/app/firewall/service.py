"""Service boundary for validated firewall operations."""

from __future__ import annotations

from app.firewall.models import FirewallRule
from app.firewall.provider import FirewallProvider
from app.firewall.validator import (
    validate_firewall_rule,
    validate_firewall_rule_name,
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
        """Validate and add a firewall rule through the configured provider."""
        validated_rule = validate_firewall_rule(rule)
        self._provider.add_rule(validated_rule)

    def remove_rule(self, name: str) -> None:
        """Validate the rule name and remove it through the configured provider."""
        validated_name = validate_firewall_rule_name(name)
        self._provider.remove_rule(validated_name)

    def rule_exists(self, name: str) -> bool:
        """Validate the rule name and query the configured provider."""
        validated_name = validate_firewall_rule_name(name)
        return self._provider.rule_exists(validated_name)
