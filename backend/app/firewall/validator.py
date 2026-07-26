"""Safety validation for firewall rule operations."""

from __future__ import annotations

import ipaddress
from pathlib import PureWindowsPath

from app.firewall.models import FirewallRule

MAX_RULE_NAME_LENGTH = 128
MAX_DESCRIPTION_LENGTH = 512
REQUIRED_RULE_PREFIX = "AI-Firewall-"
FORBIDDEN_WILDCARD_CHARS = ("*", "?", "[", "]")


class FirewallValidationError(ValueError):
    """Raised when a firewall rule fails safety validation."""


class UnsafeRuleNamespaceError(FirewallValidationError):
    """Raised when an operation targets a rule outside the AI-Firewall-* namespace."""




def validate_firewall_rule(rule: FirewallRule) -> FirewallRule:
    """
    Validate a firewall rule before it reaches a firewall provider.

    Validation here must remain independent of operating-system execution.
    """

    if not isinstance(rule, FirewallRule):
        raise FirewallValidationError("Rule must be a FirewallRule instance.")

    name = rule.name.strip()

    if not name:
        raise FirewallValidationError("Firewall rule name cannot be empty.")

    if len(name) > MAX_RULE_NAME_LENGTH:
        raise FirewallValidationError(
            f"Firewall rule name exceeds {MAX_RULE_NAME_LENGTH} characters."
        )

    remote_address = _validate_remote_address(rule.remote_address)
    program = _validate_program(rule.program)

    if remote_address is None and program is None:
        raise FirewallValidationError(
            "Firewall rule must specify a remote address or program."
        )

    description = rule.description

    if description is not None:
        description = description.strip() or None

        if description is not None and len(description) > MAX_DESCRIPTION_LENGTH:
            raise FirewallValidationError(
                f"Firewall rule description exceeds {MAX_DESCRIPTION_LENGTH} characters."
            )

    return FirewallRule(
        name=name,
        action=rule.action,
        direction=rule.direction,
        remote_address=remote_address,
        program=program,
        description=description,
    )


def _validate_remote_address(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise FirewallValidationError(
            "Remote address must be a valid IPv4/IPv6 address or CIDR network."
        ) from exc

    return str(network)


def _validate_program(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    path = PureWindowsPath(value)

    if not path.is_absolute():
        raise FirewallValidationError(
            "Program must use an absolute Windows path."
        )

    return str(path)


def validate_firewall_rule_name(name: str) -> str:
    """
    Validate and normalize a firewall rule name before provider access.
    """

    if not isinstance(name, str):
        raise FirewallValidationError("Firewall rule name must be a string.")

    name = name.strip()

    if not name:
        raise FirewallValidationError("Firewall rule name cannot be empty.")

    if len(name) > MAX_RULE_NAME_LENGTH:
        raise FirewallValidationError(
            f"Firewall rule name exceeds {MAX_RULE_NAME_LENGTH} characters."
        )

    return name


def validate_firewall_rule_namespace(name: str) -> str:
    """
    Validate that a rule name belongs to the AI-Firewall-* namespace and contains no wildcards.
    """
    if not isinstance(name, str):
        raise FirewallValidationError("Firewall rule name must be a string.")

    name = name.strip()

    if not name.startswith(REQUIRED_RULE_PREFIX):
        raise UnsafeRuleNamespaceError(
            f"Rule name '{name}' must start with required prefix '{REQUIRED_RULE_PREFIX}'."
        )

    if any(char in name for char in FORBIDDEN_WILDCARD_CHARS):
        raise UnsafeRuleNamespaceError(
            f"Rule name '{name}' cannot contain wildcard characters."
        )

    return name
