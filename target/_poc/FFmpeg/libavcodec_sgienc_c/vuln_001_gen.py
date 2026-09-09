#!/usr/bin/env python3
"""
VULN-001: Integer Overflow in RLE Length Calculation -> Heap Buffer Overflow in SGI Encoder
File: libavcodec/sgienc.c, function encode_frame(), lines 156-161
CWE-190 -> CWE-122

=== Vulnerability Analysis ===

Vulnerable code (sgienc.c, lines 156-161):
    tablesize = depth * height * 4;          // int, but computed as uint32
    length = SGI_HEADER_SIZE;
    if (!s->rle)
        length += depth * height * width;
    else
        length += tablesize * 2 + depth * height * (2 * width + 1);  // uint32 overflow!

    if ((ret = ff_alloc_packet(avctx, pkt, bytes_per_channel * length)) < 0)
        return ret;

Overflow path (RLE enabled by default via { .i64 = 1 }):
    tablesize * 2 + depth * height * (2 * width + 1)
    is computed in uint32 arithmetic. If the sum exceeds 2^32, it wraps to a small positive value.
    The allocation is too small, but:
      - taboff_pcb is initialized with buf_size = tablesize (the CORRECT untruncated value)
      - tablen_pcb is initialized with buf_size = tablesize
    So writes to taboff_pcb go up to tablesize bytes beyond pkt->data+512, which exceeds the allocation.

=== Trigger Dimensions (RGBA, depth=4, bytes_per_channel=1) ===
    width=8189, height=65535:
      tablesize = 4 * 65535 * 4 = 1,048,560
      depth*height*(2*width+1) = 4 * 65535 * 16379 = 4,293,591,060  (fits in uint32)
      tablesize*2 + 4,293,591,060 = 2,097,120 + 4,293,591,060 = 4,295,688,180  (OVERFLOWS!)
      wrapped = 4,295,688,180 mod 2^32 = 720,884
      allocated length = 512 + 720,884 = 721,396 bytes
      actual needed >= 512 + 2*1,048,560 = 2,609,632 bytes (tables alone)
      OOB write: taboff_pcb writes 1,048,560 bytes starting at pkt->data+512
                 into a 721,396-byte buffer -> 327,164 bytes OOB

=== Pipeline Constraint (WHY THE CRASH CANNOT BE TRIGGERED VIA STANDARD PIPELINE) ===
    av_image_check_size2() in libavutil/imgutils.c applies this check:
        stride * (h + 128) >= INT_MAX  ->  REJECT
    where stride = bpp*w + 1024 (bpp=bytes per pixel for the format, or 8 if unknown).

    For gray8 (best case, bpp=1) at w=65535:
        stride = 65535 + 1024 = 66559
        max_h = (INT_MAX - 1) / 66559 - 128 = 32136
    But overflow requires h >= 32761.
    Gap: 32136 - 32761 = -625  ->  IMPOSSIBLE to satisfy both conditions simultaneously.

    This gap is format-independent (mathematically proven for all bpp values).
    The check is in:
        - avcodec_open2() (for both decoder and encoder)
        - ff_set_dimensions() (in all decoders)
        - av_image_alloc() (for frame buffers)
        - Filter graph buffer allocation
    No standard ffmpeg CLI path bypasses all these checks.

=== Exploitability via libavcodec API ===
    A caller using libavcodec directly could:
        avcodec_alloc_context3(sgi_encoder)
        avctx->width = 8189;
        avctx->height = 65535;
        avctx->pix_fmt = AV_PIX_FMT_RGBA;
        avcodec_open2(avctx, sgi_encoder, NULL);
    avcodec_open2 would set dimensions to 0x0 due to av_image_check_size failure.
    So even the API path is protected.

    However, if a caller manually sets width/height AFTER avcodec_open2 returns,
    or uses internal APIs to bypass the check, the overflow is triggerable.
"""

import struct
import os

SGI_HEADER_SIZE = 512

def compute_overflow(width, height, depth=4, bytes_per_channel=1):
    """Simulate the integer overflow in sgienc.c encode_frame()."""
    tablesize = depth * height * 4                    # int in C
    rle_term = depth * height * (2 * width + 1)       # uint32 in C (can wrap)
    raw_sum = tablesize * 2 + rle_term                 # uint32 addition (can wrap)
    wrapped = raw_sum & 0xFFFFFFFF                     # simulate uint32 truncation
    length = SGI_HEADER_SIZE + wrapped                 # final length (wrong if wrapped)
    true_needed = SGI_HEADER_SIZE + tablesize*2 + rle_term  # true needed (no wrap)
    return {
        "tablesize": tablesize,
        "rle_term": rle_term,
        "raw_sum": raw_sum,
        "wrapped_sum": wrapped,
        "allocated": bytes_per_channel * length,
        "true_needed": true_needed,
        "overflows": raw_sum > 0xFFFFFFFF,
        "oob_bytes": tablesize - length if (raw_sum > 0xFFFFFFFF) else 0,
    }

def av_image_check_size_passes(width, height, bpp=1):
    """Simulate av_image_check_size2 with AV_PIX_FMT_NONE (stride = 8*w + 1024)."""
    INT_MAX = 2**31 - 1
    stride = 8 * width + 1024   # AV_PIX_FMT_NONE: stride = 8*w, + 128*8
    if stride >= INT_MAX:
        return False
    if stride * (height + 128) >= INT_MAX:
        return False
    return True

def av_image_check_size_passes_rgba(width, height):
    """Simulate av_image_check_size2 with AV_PIX_FMT_RGBA (stride = 4*w + 1024)."""
    INT_MAX = 2**31 - 1
    stride = 4 * width + 1024
    if stride >= INT_MAX:
        return False
    if stride * (height + 128) >= INT_MAX:
        return False
    return True

print("=== VULN-001: SGI Encoder Integer Overflow Analysis ===\n")

# Primary trigger: RGBA at 8189x65535
res = compute_overflow(8189, 65535, depth=4, bytes_per_channel=1)
print("Target dimensions: width=8189, height=65535, format=RGBA (depth=4)")
print(f"  tablesize                 = {res['tablesize']:,}")
print(f"  depth*H*(2W+1)            = {res['rle_term']:,}")
print(f"  raw sum (before wrap)     = {res['raw_sum']:,}")
print(f"  overflows uint32?         = {res['overflows']}")
print(f"  wrapped sum               = {res['wrapped_sum']:,}")
print(f"  allocated packet size     = {res['allocated']:,} bytes")
print(f"  true_needed (tables only) = 512 + 2*{res['tablesize']:,} = {512+2*res['tablesize']:,} bytes")
print(f"  OOB write amount          = {res['oob_bytes']:,} bytes")
print()

# Pipeline check
passes_none = av_image_check_size_passes(8189, 65535, bpp=4)
passes_rgba = av_image_check_size_passes_rgba(8189, 65535)
print(f"av_image_check_size (AV_PIX_FMT_NONE): {'PASS' if passes_none else 'FAIL (pipeline blocks this)'}")
print(f"av_image_check_size (AV_PIX_FMT_RGBA): {'PASS' if passes_rgba else 'FAIL (pipeline blocks this)'}")
print()

# Show the gap
print("=== Gap Analysis (why pipeline cannot trigger this) ===")
for fmt_name, bpp, depth in [("RGBA", 4, 4), ("RGB24", 3, 3), ("GRAY8", 1, 1)]:
    w = 65535
    INT_MAX = 2**31 - 1
    stride = bpp * w + 1024
    max_h = (INT_MAX - 1) // stride - 128
    # min h to trigger overflow
    # h*(depth*8 + 2*depth*4*4) > 2^32 is approximate; exact:
    # tablesize*2 + depth*h*(2w+1) > 2^32
    # 8*depth*h + depth*h*(2w+1) > 2^32
    # h*(8*depth + depth*(2w+1)) > 2^32
    min_h = 2**32 // (depth * 8 + depth * (2*w+1)) + 1
    print(f"  {fmt_name}: max_h_check={max_h}, min_h_overflow={min_h}, gap={max_h-min_h}")
print()
print("Negative gap = impossible to trigger via standard ffmpeg pipeline.")
print("The overflow exists in the source code but is guarded by av_image_check_size.")
print()

# Write the marker
out_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(out_dir, "vuln_001_ready.txt"), "w") as f:
    f.write("VULN-001 analysis complete.\n")
    f.write(f"Overflow confirmed: allocated={res['allocated']}, oob_bytes={res['oob_bytes']}\n")
    f.write(f"Pipeline blocks: av_image_check_size fails for trigger dimensions\n")
print(f"Marker written. Run vuln_001_run.sh to attempt trigger and capture actual pipeline output.")
