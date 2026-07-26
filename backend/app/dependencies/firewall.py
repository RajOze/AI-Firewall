"""Dependency factory for firewall service composition."""

from app.firewall.service import FirewallService
from app.firewall.windows_provider import WindowsFirewallProvider


def get_firewall_service() -> FirewallService:
    """Construct and return FirewallService configured with WindowsFirewallProvider.

    Application layer and FastAPI routes use this dependency factory to obtain
    FirewallService. FirewallService remains the single application mutation boundary,
    encapsulating the WindowsFirewallProvider host implementation detail.
    """
    provider = WindowsFirewallProvider()
    return FirewallService(provider)
