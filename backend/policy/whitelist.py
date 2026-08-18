"""System-critical process and network whitelist definitions."""
from typing import Final
import ipaddress

SYSTEM_CRITICAL_PROCESSES: Final[set[str]] = {
    "ntoskrnl.exe",
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "spoolsv.exe",
    "dwm.exe",
    "fontdrvhost.exe",
}

WHITELISTED_IPS: Final[set[str]] = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


def is_system_critical_process(process_name: str | None) -> bool:
    """Check if process is an immutable Windows OS component."""
    if not process_name:
        return False
    clean_name = process_name.strip().lower()
    if clean_name.endswith(".exe"):
        clean_name = clean_name
    return clean_name in SYSTEM_CRITICAL_PROCESSES or f"{clean_name}.exe" in SYSTEM_CRITICAL_PROCESSES


def is_whitelisted_ip(ip_str: str | None) -> bool:
    """Check if IP address is loopback, local, or infrastructure whitelisted."""
    if not ip_str:
        return False
    ip_clean = ip_str.strip()
    if ip_clean in WHITELISTED_IPS:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified
    except ValueError:
        return False
