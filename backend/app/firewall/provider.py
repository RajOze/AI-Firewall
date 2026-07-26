from abc import ABC, abstractmethod

from app.firewall.models import FirewallRule, FirewallRuleIdentity


class FirewallProvider(ABC):
    """
    Abstract boundary between AI Firewall and the host firewall.

    Implementations may interact with Windows Defender Firewall,
    while callers remain independent of operating-system details.
    """

    @abstractmethod
    def add_rule(self, rule: FirewallRule) -> FirewallRuleIdentity:
        raise NotImplementedError

    @abstractmethod
    def remove_rule(self, identity_or_name: FirewallRuleIdentity | str) -> None:
        raise NotImplementedError

    @abstractmethod
    def rule_exists(self, identity_or_name: FirewallRuleIdentity | str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_administrator(self) -> bool:
        raise NotImplementedError
