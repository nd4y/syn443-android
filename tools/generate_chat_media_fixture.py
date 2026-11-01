"""Generate synthetic instrumentation media on the build worker, never user media."""
from pathlib import Path
import subprocess

target = Path('app/src/androidTest/assets/chat-fixture.mp4')
target.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
    '-f', 'lavfi', '-i', 'testsrc2=size=1920x1080:rate=30',
    '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=44100',
    '-t', '4', '-c:v', 'libx264', '-preset', 'ultrafast', '-b:v', '6M',
    '-threads', '1', '-c:a', 'aac', '-b:a', '128k', '-movflags', '+faststart',
    '-metadata', 'location=+00.1000+000.1000/', str(target)], check=True, timeout=90)
assert 0 < target.stat().st_size < 25 * 1024 * 1024
print('Synthetic H264/AAC chat fixture generated')
