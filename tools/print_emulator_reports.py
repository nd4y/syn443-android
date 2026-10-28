from pathlib import Path
import xml.etree.ElementTree as ET

# Report failure nodes before bounded file previews, even when a large passing
# XML prefix would otherwise hide the failing codec/controller case.
failed_methods = set()
for path in sorted(Path('app/build/outputs/androidTest-results').rglob('*.xml'))[:16]:
    try:
        doc=ET.parse(path).getroot()
        for case in doc.iter('testcase'):
            for tag in ('failure','error'):
                node=case.find(tag)
                if node is not None:
                    failed_methods.add(case.get('name',''))
                    print('FAILED CASE '+case.get('classname','')+'.'+case.get('name',''))
                    print((node.text or node.get('message',''))[:8192])
    except (ET.ParseError,OSError):
        print('JUnit diagnostic could not be parsed')

# CI uses only synthetic fixtures; bound diagnostics when artifact storage is full.
remaining = 131072
for base in ("app/build/outputs/androidTest-results", "app/build/reports/androidTests"):
    paths = sorted((p for p in Path(base).rglob("*") if p.suffix in (".xml", ".log", ".txt")),
                   key=lambda p: (not any(name and name in p.name for name in failed_methods), str(p)))
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
