"""Unit tests for firewall dependency factory."""

from unittest.mock import patch

from app.dependencies.firewall import get_firewall_service
from app.firewall.service import FirewallService
from app.firewall.windows_provider import WindowsFirewallProvider


def test_get_firewall_service_returns_firewall_service_instance():
    """Verify get_firewall_service returns a FirewallService instance."""
    service = get_firewall_service()
    assert isinstance(service, FirewallService)


def test_get_firewall_service_backed_by_windows_firewall_provider():
    """Verify FirewallService returned is backed by WindowsFirewallProvider."""
    service = get_firewall_service()
    assert isinstance(service._provider, WindowsFirewallProvider)


def test_get_firewall_service_does_not_call_add_rule_or_remove_rule():
    """Verify constructing the dependency does NOT call add_rule or remove_rule on provider."""
    with patch.object(WindowsFirewallProvider, "add_rule") as mock_add, patch.object(
        WindowsFirewallProvider, "remove_rule"
    ) as mock_remove:
        service = get_firewall_service()
        assert isinstance(service, FirewallService)
        mock_add.assert_not_called()
        mock_remove.assert_not_called()


def test_no_mutation_triggered_by_obtaining_dependency():
    """Verify obtaining the dependency executes zero powershell or mutation commands."""
    with patch.object(
        WindowsFirewallProvider, "_run_powershell"
    ) as mock_powershell, patch.object(
        WindowsFirewallProvider, "add_rule"
    ) as mock_add, patch.object(
        WindowsFirewallProvider, "remove_rule"
    ) as mock_remove:
        service = get_firewall_service()
        assert isinstance(service, FirewallService)
        mock_powershell.assert_not_called()
        mock_add.assert_not_called()
        mock_remove.assert_not_called()
