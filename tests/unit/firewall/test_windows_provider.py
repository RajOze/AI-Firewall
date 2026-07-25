"""Unit tests for WindowsFirewallProvider."""

import subprocess
from unittest.mock import patch

import pytest

from app.firewall.models import FirewallAction, FirewallDirection, FirewallRule
from app.firewall.windows_provider import (
    WindowsFirewallProvider,
    WindowsFirewallProviderError,
)


def test_add_rule_allow_inbound_maps_enums_and_passes_arguments() -> None:
    """add_rule should map ALLOW to 'Allow', INBOUND to 'Inbound', and pass arguments separately."""
    provider = WindowsFirewallProvider()
    rule = FirewallRule(
        name="AllowInboundRule",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address="192.168.1.50",
        program=r"C:\App\service.exe",
        description="Allow inbound traffic",
    )

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        provider.add_rule(rule)

        mock_run.assert_called_once()
        script, *args = mock_run.call_args[0]

        # Script source checks
        assert "New-NetFirewallRule" in script
        assert "AllowInboundRule" not in script
        assert "192.168.1.50" not in script
        assert r"C:\App\service.exe" not in script
        assert "Allow inbound traffic" not in script

        # Argument vector checks
        assert args == [
            "-DisplayName",
            "AllowInboundRule",
            "-Action",
            "Allow",
            "-Direction",
            "Inbound",
            "-RemoteAddress",
            "192.168.1.50",
            "-Program",
            r"C:\App\service.exe",
            "-Description",
            "Allow inbound traffic",
        ]


def test_add_rule_block_outbound_maps_enums() -> None:
    """add_rule should map BLOCK to 'Block' and OUTBOUND to 'Outbound'."""
    provider = WindowsFirewallProvider()
    rule = FirewallRule(
        name="BlockOutboundRule",
        action=FirewallAction.BLOCK,
        direction=FirewallDirection.OUTBOUND,
    )

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        provider.add_rule(rule)

        mock_run.assert_called_once()
        _, *args = mock_run.call_args[0]

        action_idx = args.index("-Action")
        assert args[action_idx + 1] == "Block"

        dir_idx = args.index("-Direction")
        assert args[dir_idx + 1] == "Outbound"


def test_add_rule_absent_optional_fields_use_empty_strings() -> None:
    """add_rule should pass empty strings for absent optional fields."""
    provider = WindowsFirewallProvider()
    rule = FirewallRule(
        name="MinimalRule",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
        remote_address=None,
        program=None,
        description=None,
    )

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        provider.add_rule(rule)

        mock_run.assert_called_once()
        _, *args = mock_run.call_args[0]

        remote_idx = args.index("-RemoteAddress")
        assert args[remote_idx + 1] == ""

        prog_idx = args.index("-Program")
        assert args[prog_idx + 1] == ""

        desc_idx = args.index("-Description")
        assert args[desc_idx + 1] == ""


def test_add_rule_raises_provider_error_on_nonzero_exit() -> None:
    """add_rule should raise WindowsFirewallProviderError with stderr on nonzero exit code."""
    provider = WindowsFirewallProvider()
    rule = FirewallRule(
        name="FailedRule",
        action=FirewallAction.ALLOW,
        direction=FirewallDirection.INBOUND,
    )

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Access is denied."
        ),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="Access is denied."):
            provider.add_rule(rule)


def test_remove_rule_passes_name_separately_and_contains_cmdlet() -> None:
    """remove_rule should use Remove-NetFirewallRule and pass name as a separate argument."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        provider.remove_rule("RuleToRemove")

        mock_run.assert_called_once()
        script, *args = mock_run.call_args[0]

        assert "Remove-NetFirewallRule" in script
        assert "RuleToRemove" not in script
        assert args == ["-DisplayName", "RuleToRemove"]


def test_remove_rule_raises_provider_error_on_nonzero_exit() -> None:
    """remove_rule should raise WindowsFirewallProviderError with stderr on nonzero exit code."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Rule not found."
        ),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="Rule not found."):
            provider.remove_rule("NonExistentRule")


def test_rule_exists_returncode_0_returns_true() -> None:
    """rule_exists should return True when PowerShell script exits with code 0."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        result = provider.rule_exists("CheckRule")

        assert result is True
        mock_run.assert_called_once()
        script, *args = mock_run.call_args[0]

        assert "Get-NetFirewallRule" in script
        assert "-ErrorAction Stop" in script
        assert "try" in script
        assert "catch" in script
        assert "CheckRule" not in script
        assert args == ["-DisplayName", "CheckRule"]


def test_rule_exists_returncode_1_returns_false() -> None:
    """rule_exists should return False when PowerShell script exits with code 1."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
    ):
        assert provider.rule_exists("MissingRule") is False


def test_rule_exists_returncode_2_raises_provider_error() -> None:
    """rule_exists should raise WindowsFirewallProviderError when script exits with code 2."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="CIM connection error."
        ),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="CIM connection error."):
            provider.rule_exists("ErrorRule")


def test_rule_exists_unexpected_returncode_raises_provider_error() -> None:
    """rule_exists should raise WindowsFirewallProviderError on unexpected exit code (e.g. 7)."""
    provider = WindowsFirewallProvider()

    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=7, stdout="", stderr="Unexpected failure code 7."
        ),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="Unexpected exit code 7"):
            provider.rule_exists("CrashRule")


def test_add_rule_raises_value_error_for_invalid_action() -> None:
    """add_rule should raise ValueError before invoking PowerShell if action is invalid."""
    provider = WindowsFirewallProvider()
    invalid_rule = FirewallRule(
        name="InvalidActionRule",
        action="INVALID_ACTION",  # type: ignore[arg-type]
        direction=FirewallDirection.INBOUND,
    )

    with patch.object(provider, "_run_powershell") as mock_run:
        with pytest.raises(ValueError, match="Unsupported firewall action: INVALID_ACTION"):
            provider.add_rule(invalid_rule)
        mock_run.assert_not_called()


def test_add_rule_raises_value_error_for_invalid_direction() -> None:
    """add_rule should raise ValueError before invoking PowerShell if direction is invalid."""
    provider = WindowsFirewallProvider()
    invalid_rule = FirewallRule(
        name="InvalidDirectionRule",
        action=FirewallAction.ALLOW,
        direction="INVALID_DIRECTION",  # type: ignore[arg-type]
    )

    with patch.object(provider, "_run_powershell") as mock_run:
        with pytest.raises(ValueError, match="Unsupported firewall direction: INVALID_DIRECTION"):
            provider.add_rule(invalid_rule)
        mock_run.assert_not_called()
