"""Windows Firewall provider implementation for AI Firewall."""

import json
import subprocess
import sys

from app.firewall.models import (
    FirewallAction,
    FirewallDirection,
    FirewallProfileState,
    FirewallRule,
    WindowsCapabilityResult,
)
from app.firewall.provider import FirewallProvider


class WindowsFirewallProviderError(RuntimeError):
    """Raised when Windows Firewall operations fail."""


# Timeout for PowerShell command execution in seconds
POWERSHELL_TIMEOUT_SECONDS = 15

ACTION_MAP = {
    FirewallAction.ALLOW: "Allow",
    FirewallAction.BLOCK: "Block",
}

DIRECTION_MAP = {
    FirewallDirection.INBOUND: "Inbound",
    FirewallDirection.OUTBOUND: "Outbound",
}


class WindowsFirewallProvider(FirewallProvider):
    """Windows Firewall provider using PowerShell NetSecurity cmdlets."""

    def _run_powershell(self, script: str, *args: str) -> subprocess.CompletedProcess:
        """Run a fixed PowerShell script with dynamic arguments safely.

        Args:
            script: Fixed PowerShell script string (no dynamic values interpolated)
            *args: Arguments to pass to the script

        Returns:
            CompletedProcess instance from subprocess.run

        Raises:
            WindowsFirewallProviderError: If the PowerShell command times out, the executable is not found, or fails to start
        """
        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ] + list(args)
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=POWERSHELL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as e:
            raise WindowsFirewallProviderError(
                f"PowerShell command timed out after {POWERSHELL_TIMEOUT_SECONDS} seconds"
            ) from e
        except FileNotFoundError:
            raise WindowsFirewallProviderError(
                "PowerShell executable not found. Ensure powershell.exe is installed and in the PATH."
            )
        except OSError as e:
            raise WindowsFirewallProviderError(
                f"Failed to execute PowerShell command: {e}"
            ) from e

    def add_rule(self, rule: FirewallRule) -> None:
        """Add a firewall rule using New-NetFirewallRule.

        Args:
            rule: Validated FirewallRule instance

        Raises:
            ValueError: If action or direction enum is invalid
            WindowsFirewallProviderError: If PowerShell command fails
        """
        if rule.action not in ACTION_MAP:
            raise ValueError(f"Unsupported firewall action: {rule.action}")
        action_str = ACTION_MAP[rule.action]

        if rule.direction not in DIRECTION_MAP:
            raise ValueError(f"Unsupported firewall direction: {rule.direction}")
        direction_str = DIRECTION_MAP[rule.direction]

        # Fixed PowerShell script with parameter block
        script = """
        param(
            [string]$DisplayName,
            [string]$Action,
            [string]$Direction,
            [string]$RemoteAddress,
            [string]$Program,
            [string]$Description
        )

        $params = @{
            DisplayName = $DisplayName
            Action = $Action
            Direction = $Direction
        }

        if ($RemoteAddress) { $params.RemoteAddress = $RemoteAddress }
        if ($Program) { $params.Program = $Program }
        if ($Description) { $params.Description = $Description }

        New-NetFirewallRule @params
        """

        # Prepare arguments (empty strings for None values)
        remote_address = rule.remote_address if rule.remote_address is not None else ""
        program = rule.program if rule.program is not None else ""
        description = rule.description if rule.description is not None else ""

        arguments = [
            "-DisplayName",
            rule.name,
            "-Action",
            action_str,
            "-Direction",
            direction_str,
            "-RemoteAddress",
            remote_address,
            "-Program",
            program,
            "-Description",
            description,
        ]

        result = self._run_powershell(script, *arguments)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Failed to add firewall rule '{rule.name}'{error_details}"
            )

    def remove_rule(self, name: str) -> None:
        """Remove a firewall rule using Remove-NetFirewallRule.

        Args:
            name: Display name of the rule to remove

        Raises:
            WindowsFirewallProviderError: If PowerShell command fails
        """
        # Fixed PowerShell script with parameter block
        script = """
        param(
            [string]$DisplayName
        )

        Remove-NetFirewallRule -DisplayName $DisplayName
        """

        arguments = ["-DisplayName", name]

        result = self._run_powershell(script, *arguments)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Failed to remove firewall rule '{name}'{error_details}"
            )

    def rule_exists(self, name: str) -> bool:
        """Check if a firewall rule exists using Get-NetFirewallRule.

        Args:
            name: Display name of the rule to check

        Returns:
            True if rule exists, False if not found

        Raises:
            WindowsFirewallProviderError: If PowerShell command fails unexpectedly
        """
        # Fixed PowerShell script that exits with specific codes
        script = """
        param(
            [string]$DisplayName
        )

        try {
            $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction Stop
            if ($rule) {
                exit 0
            } else {
                exit 1
            }
        } catch {
            $cat = "$($_.CategoryInfo.Category)"
            $errId = "$($_.FullyQualifiedErrorId)"
            $msg = "$($_.Exception.Message)"

            if ($cat -eq 'ObjectNotFound' -or
                $errId -like '*ObjectNotFound*' -or
                $errId -like '*InstanceNotFound*' -or
                $msg -like '*No matching*' -or
                $msg -like '*not found*') {
                exit 1
            } else {
                [Console]::Error.WriteLine($_)
                exit 2
            }
        }
        """

        arguments = ["-DisplayName", name]
        result = self._run_powershell(script, *arguments)

        if result.returncode == 0:
            return True
        elif result.returncode == 1:
            return False
        elif result.returncode == 2:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Failed to check existence of firewall rule '{name}'{error_details}"
            )
        else:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Unexpected exit code {result.returncode} checking firewall rule '{name}'{error_details}"
            )

    def is_administrator(self) -> bool:
        """Check if the current process is running with administrator privileges.

        Returns:
            True if running with administrator privileges, False if not.

        Raises:
            WindowsFirewallProviderError: If the PowerShell command fails unexpectedly.
        """
        script = """
        try {
            $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if ($isAdmin) {
                exit 0
            } else {
                exit 1
            }
        } catch {
            [Console]::Error.WriteLine($_)
            exit 2
        }
        """

        result = self._run_powershell(script)
        if result.returncode == 0:
            return True
        elif result.returncode == 1:
            return False
        elif result.returncode == 2:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Failed to check administrator privileges{error_details}"
            )
        else:
            stderr = result.stderr.strip()
            error_details = f": {stderr}" if stderr else ""
            raise WindowsFirewallProviderError(
                f"Unexpected exit code {result.returncode} checking administrator privileges{error_details}"
            )

    def get_capabilities(self) -> WindowsCapabilityResult:
        """Inspect host capabilities and firewall profile statuses in read-only mode.

        Returns:
            WindowsCapabilityResult dataclass instance representing host readiness.
        """
        is_windows = sys.platform == "win32"
        if not is_windows:
            return WindowsCapabilityResult(
                is_windows=False,
                powershell_available=False,
                netsecurity_available=False,
                is_administrator=False,
                firewall_profiles=[],
            )

        powershell_available = False
        is_admin = False
        netsecurity_available = False
        firewall_profiles: list[FirewallProfileState] = []

        # 1. Check PowerShell availability
        try:
            ping_res = self._run_powershell("exit 0")
            if ping_res.returncode == 0:
                powershell_available = True
        except WindowsFirewallProviderError:
            powershell_available = False

        if not powershell_available:
            return WindowsCapabilityResult(
                is_windows=True,
                powershell_available=False,
                netsecurity_available=False,
                is_administrator=False,
                firewall_profiles=[],
            )

        # 2. Check Administrator status
        try:
            is_admin = self.is_administrator()
        except WindowsFirewallProviderError:
            is_admin = False

        # 3. Check NetSecurity availability and retrieve Firewall Profiles
        script = """
        try {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                exit 1
            }
            $profiles = Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled
            if (-not $profiles) {
                exit 1
            }
            $profiles | ConvertTo-Json -Compress
        } catch {
            [Console]::Error.WriteLine($_)
            exit 2
        }
        """

        try:
            result = self._run_powershell(script)
        except WindowsFirewallProviderError:
            result = None

        if result is not None and result.returncode == 0:
            netsecurity_available = True
            raw_stdout = result.stdout.strip()
            if not raw_stdout:
                raise WindowsFirewallProviderError(
                    "Failed to parse firewall profiles output: empty response"
                )

            try:
                data = json.loads(raw_stdout)
            except json.JSONDecodeError as e:
                raise WindowsFirewallProviderError(
                    "Failed to parse firewall profiles output: invalid JSON"
                ) from e

            if isinstance(data, dict):
                data = [data]

            if not isinstance(data, list) or not data:
                raise WindowsFirewallProviderError(
                    "Failed to parse firewall profiles output: expected non-empty list of profile objects"
                )

            for item in data:
                if not isinstance(item, dict) or "Name" not in item or "Enabled" not in item:
                    raise WindowsFirewallProviderError(
                        "Failed to parse firewall profiles output: profile object missing 'Name' or 'Enabled'"
                    )
                name = str(item["Name"])
                raw_enabled = item["Enabled"]
                if not isinstance(raw_enabled, (bool, int, str)):
                    raise WindowsFirewallProviderError(
                        "Failed to parse firewall profiles output: invalid 'Enabled' value type"
                    )
                enabled = raw_enabled in (1, True, "1", "True", "Enabled")
                firewall_profiles.append(
                    FirewallProfileState(name=name, enabled=enabled)
                )

        return WindowsCapabilityResult(
            is_windows=True,
            powershell_available=powershell_available,
            netsecurity_available=netsecurity_available,
            is_administrator=is_admin,
            firewall_profiles=firewall_profiles,
        )

    def get_capability_result(self) -> WindowsCapabilityResult:
        """Alias for get_capabilities."""
        return self.get_capabilities()