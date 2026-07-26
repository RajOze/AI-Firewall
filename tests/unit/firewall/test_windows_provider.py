"""Unit tests for WindowsFirewallProvider."""

import subprocess
from unittest.mock import patch

import pytest

from app.firewall.models import (
    FirewallAction,
    FirewallDirection,
    FirewallProfileState,
    FirewallRule,
    WindowsCapabilityResult,
)
from app.firewall.windows_provider import (
    POWERSHELL_TIMEOUT_SECONDS,
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


def test_run_powershell_executes_with_timeout_and_no_shell() -> None:
    """_run_powershell should pass timeout and not use shell=True."""
    provider = WindowsFirewallProvider()
    with patch(
        "subprocess.run",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_sub_run:
        provider._run_powershell("Write-Host Test", "arg1")

        mock_sub_run.assert_called_once()
        _, kwargs = mock_sub_run.call_args
        assert kwargs.get("timeout") == POWERSHELL_TIMEOUT_SECONDS
        assert kwargs.get("shell") is not True


def test_run_powershell_raises_provider_error_on_timeout() -> None:
    """_run_powershell should convert subprocess.TimeoutExpired to WindowsFirewallProviderError."""
    provider = WindowsFirewallProvider()
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=15),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="timed out"):
            provider._run_powershell("Write-Host Test")


def test_run_powershell_raises_provider_error_on_file_not_found() -> None:
    """_run_powershell should convert FileNotFoundError to WindowsFirewallProviderError."""
    provider = WindowsFirewallProvider()
    with patch("subprocess.run", side_effect=FileNotFoundError("powershell.exe not found")):
        with pytest.raises(WindowsFirewallProviderError, match="PowerShell executable not found"):
            provider._run_powershell("Write-Host Test")


def test_run_powershell_raises_provider_error_on_os_error() -> None:
    """_run_powershell should convert OSError to WindowsFirewallProviderError."""
    provider = WindowsFirewallProvider()
    with patch("subprocess.run", side_effect=OSError("Permission denied")):
        with pytest.raises(
            WindowsFirewallProviderError, match="Failed to execute PowerShell command"
        ):
            provider._run_powershell("Write-Host Test")


def test_is_administrator_returns_true_when_exit_code_0() -> None:
    """is_administrator should return True when process exits with 0."""
    provider = WindowsFirewallProvider()
    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ) as mock_run:
        assert provider.is_administrator() is True
        mock_run.assert_called_once()
        script = mock_run.call_args[0][0]
        assert "WindowsBuiltInRole" in script


def test_is_administrator_returns_false_when_exit_code_1() -> None:
    """is_administrator should return False when process exits with 1."""
    provider = WindowsFirewallProvider()
    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
    ):
        assert provider.is_administrator() is False


def test_is_administrator_raises_provider_error_on_exit_code_2() -> None:
    """is_administrator should raise WindowsFirewallProviderError when script fails with exit code 2."""
    provider = WindowsFirewallProvider()
    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=2, stdout="", stderr="Security check exception."
        ),
    ):
        with pytest.raises(
            WindowsFirewallProviderError, match="Failed to check administrator privileges"
        ):
            provider.is_administrator()


def test_is_administrator_raises_provider_error_on_unexpected_exit_code() -> None:
    """is_administrator should raise WindowsFirewallProviderError on unexpected exit code."""
    provider = WindowsFirewallProvider()
    with patch.object(
        provider,
        "_run_powershell",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=99, stdout="", stderr="Fatal error."
        ),
    ):
        with pytest.raises(WindowsFirewallProviderError, match="Unexpected exit code 99"):
            provider.is_administrator()


def test_get_capabilities_non_windows_platform() -> None:
    """get_capabilities should return is_windows=False and default False/empty on non-Windows platforms."""
    provider = WindowsFirewallProvider()
    with patch("sys.platform", "linux"):
        res = provider.get_capabilities()
        assert res.is_windows is False
        assert res.powershell_available is False
        assert res.netsecurity_available is False
        assert res.is_administrator is False
        assert res.firewall_profiles == []


def test_get_capabilities_windows_powershell_unavailable() -> None:
    """get_capabilities should detect is_windows=True but powershell_available=False if PowerShell fails."""
    provider = WindowsFirewallProvider()
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=WindowsFirewallProviderError("PowerShell executable not found"),
        ):
            res = provider.get_capabilities()
            assert res.is_windows is True
            assert res.powershell_available is False
            assert res.netsecurity_available is False
            assert res.is_administrator is False
            assert res.firewall_profiles == []


def test_get_capabilities_powershell_available_netsecurity_unavailable() -> None:
    """get_capabilities should report netsecurity_available=False if Get-NetFirewallProfile fails."""
    provider = WindowsFirewallProvider()
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="Missing module"),
            ],
        ):
            res = provider.get_capabilities()
            assert res.is_windows is True
            assert res.powershell_available is True
            assert res.is_administrator is False
            assert res.netsecurity_available is False
            assert res.firewall_profiles == []


def test_get_capabilities_administrator_true_and_profiles_parsed() -> None:
    """get_capabilities should report is_administrator=True and parse firewall profiles correctly."""
    provider = WindowsFirewallProvider()
    json_stdout = (
        '[{"Name": "Domain", "Enabled": 1}, '
        '{"Name": "Private", "Enabled": 1}, '
        '{"Name": "Public", "Enabled": 0}]'
    )
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout=json_stdout, stderr=""),
            ],
        ):
            res = provider.get_capabilities()
            assert res.is_windows is True
            assert res.powershell_available is True
            assert res.is_administrator is True
            assert res.netsecurity_available is True
            assert len(res.firewall_profiles) == 3
            assert res.firewall_profiles[0] == FirewallProfileState(name="Domain", enabled=True)
            assert res.firewall_profiles[1] == FirewallProfileState(name="Private", enabled=True)
            assert res.firewall_profiles[2] == FirewallProfileState(name="Public", enabled=False)


def test_get_capabilities_single_profile_dict_and_string_enabled() -> None:
    """get_capabilities should parse single dict output and string enabled values correctly."""
    provider = WindowsFirewallProvider()
    json_stdout = '{"Name": "Public", "Enabled": "True"}'
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout=json_stdout, stderr=""),
            ],
        ):
            res = provider.get_capabilities()
            assert res.is_windows is True
            assert res.powershell_available is True
            assert res.is_administrator is False
            assert res.netsecurity_available is True
            assert res.firewall_profiles == [FirewallProfileState(name="Public", enabled=True)]


def test_get_capabilities_malformed_json_raises_provider_error() -> None:
    """get_capabilities should raise WindowsFirewallProviderError when stdout is malformed JSON."""
    provider = WindowsFirewallProvider()
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout="[INVALID JSON", stderr=""),
            ],
        ):
            with pytest.raises(
                WindowsFirewallProviderError, match="Failed to parse firewall profiles output: invalid JSON"
            ):
                provider.get_capabilities()


def test_get_capabilities_missing_required_fields_raises_provider_error() -> None:
    """get_capabilities should raise WindowsFirewallProviderError when profile object missing required fields."""
    provider = WindowsFirewallProvider()
    json_stdout = '[{"Name": "Domain"}]'
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout=json_stdout, stderr=""),
            ],
        ):
            with pytest.raises(
                WindowsFirewallProviderError,
                match="Failed to parse firewall profiles output: profile object missing 'Name' or 'Enabled'",
            ):
                provider.get_capabilities()


def test_get_capabilities_invalid_enabled_type_raises_provider_error() -> None:
    """get_capabilities should raise WindowsFirewallProviderError when 'Enabled' field type is invalid."""
    provider = WindowsFirewallProvider()
    json_stdout = '[{"Name": "Domain", "Enabled": [1, 2]}]'
    with patch("sys.platform", "win32"):
        with patch.object(
            provider,
            "_run_powershell",
            side_effect=[
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
                subprocess.CompletedProcess(args=[], returncode=0, stdout=json_stdout, stderr=""),
            ],
        ):
            with pytest.raises(
                WindowsFirewallProviderError,
                match="Failed to parse firewall profiles output: invalid 'Enabled' value type",
            ):
                provider.get_capabilities()


def test_get_capability_result_alias_returns_capabilities() -> None:
    """get_capability_result alias should call get_capabilities."""
    provider = WindowsFirewallProvider()
    with patch("sys.platform", "linux"):
        res = provider.get_capability_result()
        assert res == provider.get_capabilities()



