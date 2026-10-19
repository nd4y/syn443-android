from pathlib import Path
for base in ('app/build/outputs/androidTest-results','app/build/reports/androidTests'):
    paths=sorted(p for p in Path(base).rglob('*') if p.suffix in ('.xml','.log','.txt'))
    for p in paths[:8]:
        print(f'REPORT {p} bytes={p.stat().st_size}')
        with p.open('rb') as f:
            if p.suffix != '.xml':
                f.seek(max(0,p.stat().st_size-32768))
            content=f.read(32768).decode('utf-8','replace')
        print(''.join(c for c in content if c in '\n\t' or ord(c)>=32))
