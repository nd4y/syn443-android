from pathlib import Path
import sys,zipfile,json,subprocess,tempfile
from check_apk import check_elf

path=Path(sys.argv[1])
root=Path(__file__).resolve().parent.parent
expected='go'+json.loads((root/'native/engine-lock.json').read_text())['go']
with zipfile.ZipFile(path) as archive:
    for abi in ('arm64-v8a','x86_64'):
        payload=archive.read(f'jni/{abi}/libgojni.so')
        check_elf(payload,abi)
        with tempfile.TemporaryDirectory() as directory:
            library=Path(directory)/'libgojni.so';library.write_bytes(payload)
            metadata=subprocess.check_output(['go','version','-m',str(library)],text=True)
            assert metadata.splitlines()[0].rsplit(': ',1)[-1]==expected, 'Embedded runtime differs from patched engine lock'
    assert 'classes.jar' in archive.namelist()
print('Embedded Go engine: both primary ABIs and ELF16KiB alignment valid')
