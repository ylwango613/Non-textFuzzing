# VULN 001: Integer Overflow in max_pkt_size → OOB Heap Write in PCX Encoder

## Summary

- **CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-based Buffer Overflow)
- **File**: `libavcodec/pcxenc.c`, line 136
- **Function**: `pcx_encode_frame()`

## Root Cause

`max_pkt_size` is declared as `int` (line 93). The computation at line 136:

```c
max_pkt_size = 128 + avctx->height * 2 * line_bytes * nplanes + (pal ? 256*3+1 : 0);
```

For RGB24 input (nplanes=3, bpp=8):
- `line_bytes = (width * 8 + 7) >> 3 = width` (for even widths), rounded to even
- With width=22000: `line_bytes = 22000`
- With height=35000: `35000 * 2 * 22000 * 3 = 4,620,000,000 > INT_MAX (2,147,483,647)`

The multiplication overflows signed 32-bit integer (undefined behavior in C standard; in practice wraps to ~325,032,704 on x86-64). Adding 128 gives `max_pkt_size ≈ 325,032,832` (~325 MB).

## Exploit Chain

1. `ff_alloc_packet(avctx, pkt, max_pkt_size)` allocates only ~325 MB packet buffer.
2. The encoder loop (`for (y = 0; y < avctx->height; y++)`) calls `pcx_rle_encode()` for all 35,000 rows, attempting to write ~4.62 GB of pixel data.
3. After writing ~325 MB (~14,774 rows), subsequent writes go past the end of the allocated heap buffer.
4. ASAN detects `heap-buffer-overflow` and aborts.

Note: The bounds check at line 98-101 (`if (avctx->width > 65535 || avctx->height > 65535)`) passes because 22000 and 35000 are both ≤ 65535.

## Trigger Command

```bash
ffmpeg -f lavfi -i 'color=c=black:s=22000x35000:r=1' -vframes 1 \
    -vf format=rgb24 -vcodec pcx -f image2 out.pcx
```

The lavfi `color` source generates the frame entirely in memory (~2.15 GB for the input frame), avoiding the need for a large input file on disk.

## Memory Requirements

- Input frame: 22000 × 35000 × 3 = ~2.15 GB (allocated by lavfi)
- PCX packet buffer (overflowed): ~325 MB
- Total peak: ~2.5 GB; requires system with ≥ 4 GB free RAM

## Fix

Cast to `int64_t` before the multiplication:

```c
max_pkt_size = 128 + (int64_t)avctx->height * 2 * line_bytes * nplanes + (pal ? 256*3+1 : 0);
if (max_pkt_size > INT_MAX / 2) {
    av_log(avctx, AV_LOG_ERROR, "frame too large\n");
    return AVERROR(EINVAL);
}
```
