"""Generate synthetic instrumentation media on the build worker, never user media."""
from pathlib import Path
import json
import subprocess
import tempfile

target = Path('app/src/androidTest/assets/chat-fixture.mp4')
target.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
    '-f', 'lavfi', '-i', 'testsrc2=size=1920x1080:rate=30',
    '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=44100',
    '-t', '4', '-c:v', 'libx264', '-preset', 'ultrafast', '-b:v', '6M',
    '-threads', '1', '-c:a', 'aac', '-b:a', '128k', '-movflags', '+faststart',
    '-metadata', 'location=+00.1000+000.1000/', str(target)], check=True, timeout=90)
assert 0 < target.stat().st_size < 25 * 1024 * 1024
# Different corner colors make cropping, letterboxing and incorrect rotation observable.
def geometry_clip(path, size):
    subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
        '-f', 'lavfi', '-i', f'color=c=lime:size={size}:rate=12',
        '-vf', 'drawbox=x=0:y=0:w=iw/2:h=ih:color=red:t=fill,'
               'drawbox=x=0:y=0:w=iw/2:h=ih/2:color=blue:t=fill',
        '-t', '1', '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-threads', '1',
        str(path)], check=True, timeout=30)

geometry_clip(target.with_name('chat-square.mp4'), '960x960')
rotated = target.with_name('chat-rotated.mp4')
with tempfile.TemporaryDirectory() as directory:
    landscape = Path(directory) / 'landscape.mp4'
    geometry_clip(landscape, '320x240')
    subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-nostdin', '-y',
        '-display_rotation:v:0', '90', '-i', str(landscape), '-c', 'copy', str(rotated)],
        check=True, timeout=30)
rotation = subprocess.check_output(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
    '-show_entries', 'stream=width,height:stream_side_data=rotation', '-of', 'json', str(rotated)],
    text=True, timeout=15)
stream, = json.loads(rotation)['streams']
assert (stream['width'], stream['height']) == (320, 240)
assert any(abs(item.get('rotation', 0)) == 90 for item in stream.get('side_data_list', [])), \
    'Rotated fixture requires a quarter-turn MP4 display matrix'
print('Generated synthetic chat clips, including a verified 90-degree display transform')
