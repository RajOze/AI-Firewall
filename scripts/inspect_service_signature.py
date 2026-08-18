from pathlib import Path

print("=== app/firewall/models.py ===")
models_path = Path("backend/app/firewall/models.py")
if models_path.exists():
    print(models_path.read_text(encoding="utf-8"))

print("\n=== app/firewall/service.py (add_rule excerpt) ===")
service_path = Path("backend/app/firewall/service.py")
if service_path.exists():
    content = service_path.read_text(encoding="utf-8")
    for line in content.splitlines():
        if "def add_rule" in line or "def __init__" in line or "class FirewallService" in line:
            print("  ", line)
