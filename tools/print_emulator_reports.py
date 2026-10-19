from pathlib import Path

# CI uses only synthetic fixtures; bound diagnostics when artifact storage is full.
remaining = 131072
for base in ("app/build/outputs/androidTest-results", "app/build/reports/androidTests"):
    paths = sorted(p for p in Path(base).rglob("*") if p.suffix in (".xml", ".log", ".txt"))
    for path in paths[:8]:
        if remaining <= 0:
            break
        limit = min(16384, remaining)
        print(f"REPORT {path} bytes={path.stat().st_size}")
        with path.open("rb") as stream:
            if path.suffix != ".xml":
                stream.seek(max(0, path.stat().st_size - limit))
            data = stream.read(limit)
        remaining -= len(data)
        text = data.decode("utf-8", "replace")
        print("".join(char for char in text if char in "\n\t" or ord(char) >= 32))
