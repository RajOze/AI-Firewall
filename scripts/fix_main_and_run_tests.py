from pathlib import Path

main_py_path = Path("backend/app/main.py")
if main_py_path.exists():
    # Read with utf-8-sig to automatically strip any existing BOM
    content = main_py_path.read_text(encoding="utf-8-sig")
    
    # Clean out any stray BOM characters
    content = content.replace("\ufeff", "").strip()
    
    # Ensure advisory_router is imported
    if "from backend.app.api.advisory import router as advisory_router" not in content:
        import_line = "from backend.app.api.advisory import router as advisory_router\n"
        content = import_line + content
        
    # Ensure advisory_router is mounted
    if "app.include_router(advisory_router)" not in content:
        content += "\napp.include_router(advisory_router)\n"

    # Write back clean UTF-8 (without BOM)
    main_py_path.write_text(content, encoding="utf-8")
    print("Successfully cleaned backend/app/main.py and registered advisory_router")
else:
    print("Error: backend/app/main.py not found")
