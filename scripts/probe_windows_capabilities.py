"""Read-only capability probe script for Windows Firewall host integration."""

import os
import sys

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../backend")))

from app.firewall.windows_provider import WindowsFirewallProvider


def main() -> None:
    """Run read-only capability probe and display host status."""
    print("=============================================")
    print(" AI Firewall: Windows Host Capability Probe ")
    print("=============================================")

    provider = WindowsFirewallProvider()
    result = provider.get_capabilities()

    print(f"Is Windows Platform:     {result.is_windows}")
    print(f"PowerShell Available:    {result.powershell_available}")
    print(f"NetSecurity Available:   {result.netsecurity_available}")
    print(f"Administrator Privs:     {result.is_administrator}")
    print("---------------------------------------------")
    print("Firewall Profiles:")
    if result.firewall_profiles:
        for profile in result.firewall_profiles:
            status = "Enabled" if profile.enabled else "Disabled"
            print(f"  - Profile: {profile.name:<10} | Status: {status}")
    else:
        print("  (None or Unavailable)")
    print("=============================================")


if __name__ == "__main__":
    main()
