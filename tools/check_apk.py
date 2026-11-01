"""Validate ELF PT_LOAD alignment for primary supported APK ABIs."""
from pathlib import Path
import struct,sys,zipfile

def check_elf(data: bytes, abi: str) -> None:
    if len(data)<64 or data[:6]!=b"\x7fELF\x02\x01":
        raise ValueError("Expected little-endian ELF64")
    machine=struct.unpack_from("<H",data,18)[0]
    if machine!={"arm64-v8a":183,"x86_64":62}[abi]:
        raise ValueError("ABI/machine mismatch")
    phoff=struct.unpack_from("<Q",data,32)[0]
    size,count=struct.unpack_from("<HH",data,54)
    if size<56 or not 0<count<=4096 or phoff+size*count>len(data):
        raise ValueError("Invalid program header bounds")
    loads=0
    for i in range(count):
        offset=phoff+i*size
        if struct.unpack_from("<I",data,offset)[0]!=1: continue
        loads+=1
        file_offset,address=struct.unpack_from("<QQ",data,offset+8)
        alignment=struct.unpack_from("<Q",data,offset+48)[0]
        if alignment<16384 or alignment&(alignment-1) or file_offset%alignment!=address%alignment:
            raise ValueError("PT_LOAD does not support16KiB pages")
    if not loads: raise ValueError("No load segments")

def check_apk(path: Path) -> int:
    count=0
    seen=set()
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            parts=info.filename.split("/")
            if len(parts)!=3 or parts[0]!="lib" or parts[1] not in {"arm64-v8a","x86_64"} or not parts[2].endswith(".so"): continue
            if info.file_size>128*1024*1024: raise ValueError("Native library exceeds size bound")
            check_elf(archive.read(info),parts[1]);seen.add(parts[1]);count+=1
    if seen!={"arm64-v8a","x86_64"}: raise ValueError("Missing primary native ABI")
    return count

if __name__=="__main__":
    print(f"APK ELF16KiB: {check_apk(Path(sys.argv[1]))} primary native libraries passed")

