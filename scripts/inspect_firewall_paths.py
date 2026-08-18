import os
from pathlib import Path

# 1. Locate where firewall service and models are defined
firewall_service_files = list(Path(".").rglob("*firewall*service*.py"))
print("Found firewall service files:", firewall_service_files)

firewall_model_files = list(Path(".").rglob("*firewall*model*.py"))
print("Found firewall model files:", firewall_model_files)

# Determine the correct import module
# Check if backend/app/firewall exists or app/firewall
if Path("backend/app/firewall/service.py").exists() or Path("app/firewall/service.py").exists():
    firewall_svc_import = "from app.firewall.service import FirewallService"
    firewall_models_import = "from app.firewall.models import FirewallAction, FirewallDirection, FirewallProtocol, FirewallRuleCreate"
elif Path("backend/firewall/service.py").exists():
    firewall_svc_import = "from backend.firewall.service import FirewallService"
    firewall_models_import = "from backend.firewall.models import FirewallAction, FirewallDirection, FirewallProtocol, FirewallRuleCreate"
else:
    # Search for FirewallService definition
    for py_file in Path(".").rglob("*.py"):
        if ".venv" in py_file.parts or ".git" in py_file.parts:
            continue
        try:
            content = py_file.read_text(encoding="utf-8")
            if "class FirewallService" in content:
                print(f"FirewallService found in: {py_file}")
                # Convert file path to import
                parts = list(py_file.with_suffix("").parts)
                if parts[0] == "backend" and parts[1] == "app":
                    mod_path = ".".join(parts[1:])  # app.xxx.service
                else:
                    mod_path = ".".join(parts)
                firewall_svc_import = f"from {mod_path} import FirewallService"
                print(f"Using svc import: {firewall_svc_import}")
        except Exception:
            pass

# Let's inspect backend/app/dependencies/firewall.py to see how it imports FirewallService
dep_firewall_path = Path("backend/app/dependencies/firewall.py")
if dep_firewall_path.exists():
    dep_content = dep_firewall_path.read_text(encoding="utf-8")
    print("--- backend/app/dependencies/firewall.py content ---")
    print(dep_content)
    print("----------------------------------------------------")
