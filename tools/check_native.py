from pathlib import Path
import sys,zipfile
from check_apk import check_elf

path=Path(sys.argv[1])
with zipfile.ZipFile(path) as archive:
    for abi in ('arm64-v8a','x86_64'):
        check_elf(archive.read(f'jni/{abi}/libgojni.so'),abi)
    assert 'classes.jar' in archive.namelist()
print('Embedded Go engine: both primary ABIs and ELF16KiB alignment valid')
