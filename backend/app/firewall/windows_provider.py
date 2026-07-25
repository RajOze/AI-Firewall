"""Windows Firewall provider implementation for AI Firewall."""

import subprocess

from app.firewall.models import FirewallAction, FirewallDirection, FirewallRule
from app.firewall.provider import FirewallProvider


class WindowsFirewallProviderError(RuntimeError):
    """Raised when Windows Firewall operations fail."""


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
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

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