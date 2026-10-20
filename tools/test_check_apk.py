import struct,unittest
from check_apk import check_elf

def elf():
    data=bytearray(120);data[:6]=b"\x7fELF\x02\x01"
    struct.pack_into("<H",data,18,183)
    struct.pack_into("<Q",data,32,64)
    struct.pack_into("<HH",data,54,56,1)
    struct.pack_into("<I",data,64,1)
    struct.pack_into("<Q",data,112,16384)
    return data

class ElfTests(unittest.TestCase):
    def test_valid_16k(self):
        check_elf(bytes(elf()),"arm64-v8a")
    def test_4k_rejected(self):
        data=elf();struct.pack_into("<Q",data,112,4096)
        with self.assertRaises(ValueError):check_elf(bytes(data),"arm64-v8a")
    def test_wrong_machine_rejected(self):
        with self.assertRaises(ValueError):check_elf(bytes(elf()),"x86_64")
    def test_truncated_rejected(self):
        for length in (0,63,119):
            with self.assertRaises(ValueError):check_elf(bytes(elf()[:length]),"arm64-v8a")
    def test_congruence_rejected(self):
        data=elf();struct.pack_into("<Q",data,72,1)
        with self.assertRaises(ValueError):check_elf(bytes(data),"arm64-v8a")
    def test_bad_headers_rejected(self):
        data=elf();struct.pack_into("<H",data,56,4097)
        with self.assertRaises(ValueError):check_elf(bytes(data),"arm64-v8a")
    def test_missing_load_rejected(self):
        data=elf();struct.pack_into("<I",data,64,0)
        with self.assertRaises(ValueError):check_elf(bytes(data),"arm64-v8a")
    def test_bad_alignment_rejected(self):
        data=elf();struct.pack_into("<Q",data,112,16385)
        with self.assertRaises(ValueError):check_elf(bytes(data),"arm64-v8a")
if __name__=="__main__":unittest.main()

