from dataclasses import dataclass
from enum import Enum


class FirewallAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class FirewallDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


@dataclass(frozen=True)
class FirewallRule:
    """
    Internal representation of a Windows Firewall rule request.
    """

    name: str
    action: FirewallAction
    direction: FirewallDirection
    remote_address: str | None = None
    program: str | None = None
    description: str | None = None
