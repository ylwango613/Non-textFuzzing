#!/usr/bin/env python3
"""
PoC generator for:
  VULN 001 - Integer Overflow in buf_size Computation in s302m_encode2_frame()
  Source: libavcodec/s302menc.c, lines 76-99

The vulnerability triggers when a frame with nb_samples = 536870912 (2^29)
is passed to the s302m encoder with nb_channels=2 and bits_per_raw_sample=16.

  nb_samples * nb_channels * (bits_per_raw_sample + 4)
= 536870912  *     2       *         20
= 21474836480
= 5 * 2^32
= 0  (in int32 arithmetic)

So buf_size = AES3_HEADER_LEN + 0/8 = 4, bypassing the guard check:
  if (buf_size - AES3_HEADER_LEN > UINT16_MAX)  =>  0 > 65535  => false (bypassed!)

Then ff_get_encode_buffer allocates exactly 4 bytes, but the write loop
runs for 536870912 samples * 5 bytes each = ~2.5 GB of heap overflow.

Trigger approach:
  We use FFmpeg's built-in lavfi source 'anullsrc' (silent audio) with the
  'asetnsamples' filter to create exactly 536870912 samples per frame.
  No separate crafted media file is needed.

  The command is in vuln_001_run.sh.

Memory note:
  A 536870912-sample stereo s16 frame is 536870912 * 2 * 2 = 2,147,483,648 bytes (2 GB).
  The system needs at least 2 GB of free RAM to hold the frame before the overflow fires.
  With ASAN instrumented binary, the heap overflow is detected immediately on the first
  out-of-bounds write (after just 1 sample, 5 bytes into a 4-byte allocation).
"""

import struct
import os

out_dir = os.path.dirname(os.path.abspath(__file__))

# Write a small marker file documenting the expected overflow parameters.
info = {
    "nb_samples": 536870912,
    "nb_channels": 2,
    "bits_per_raw_sample": 16,
    "factor": 536870912 * 2 * 20,
    "factor_mod_2pow32": (536870912 * 2 * 20) % (2**32),
    "computed_buf_size": 4 + (536870912 * 2 * 20) % (2**32) // 8,
    "actual_needed_bytes": 4 + (536870912 * 2 * 20) // 8,
    "frame_data_bytes": 536870912 * 2 * 2,
}

print("Overflow analysis:")
for k, v in info.items():
    print(f"  {k} = {v}")

assert info["factor_mod_2pow32"] == 0, "Expected zero wrap"
assert info["computed_buf_size"] == 4, "Expected buf_size = 4"

marker_path = os.path.join(out_dir, "vuln_001_analysis.txt")
with open(marker_path, "w") as f:
    for k, v in info.items():
        f.write(f"{k} = {v}\n")

print(f"\nAnalysis written to: {marker_path}")
print("\nNo separate input file is required — trigger uses 'anullsrc' lavfi source.")
print("Run vuln_001_run.sh to attempt the crash.")
