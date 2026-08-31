from pathlib import Path

repo_path = Path("database/repositories/event_repository.py")
if repo_path.exists():
    content = repo_path.read_text(encoding="utf-8")
    if "_memory_events" not in content:
        # Inject _memory_events alias or attribute into __init__
        content = content.replace(
            "def __init__(self",
            "def __init__(self\n        self._memory_events = []\n"
        )
        repo_path.write_text(content, encoding="utf-8")
        print("Patched EventRepository with _memory_events")
