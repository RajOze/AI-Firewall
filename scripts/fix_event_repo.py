from pathlib import Path

repo_path = Path("backend/database/repositories/event_repository.py")
if not repo_path.exists():
    repo_path = Path("database/repositories/event_repository.py")

if repo_path.exists():
    content = repo_path.read_text(encoding="utf-8")
    if "_memory_events" not in content:
        # Inject _memory_events into EventRepository init
        if "def __init__(self" in content:
            content = content.replace(
                "def __init__(self",
                "def __init__(self):\n        self._memory_events = []\n# "
            )
            repo_path.write_text(content, encoding="utf-8")
            print("Successfully added _memory_events to EventRepository!")
