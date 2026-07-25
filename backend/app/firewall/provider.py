from abc import ABC, abstractmethod

from app.firewall.models import FirewallRule


class FirewallProvider(ABC):
    """
    Abstract boundary between AI Firewall and the host firewall.

    Implementations may interact with Windows Defender Firewall,
    while callers remain independent of operating-system details.
    """

    @abstractmethod
    def add_rule(self, rule: FirewallRule) -> None:
        raise NotImplementedError

    @abstractmethod
    def remove_rule(self, name: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def rule_exists(self, name: str) -> bool:
        raise NotImplementedError
