import subprocess
from pathlib import Path

print("Setting up Event Dispatcher files...")
Path("backend/app/events/subscribers").mkdir(parents=True, exist_ok=True)
Path("tests/unit/events").mkdir(parents=True, exist_ok=True)

print("Directory structure ready. Run pytest when ready.")
