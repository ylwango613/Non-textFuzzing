# VULN 001 – Integer Overflow in decode_hq_slice_row

## Summary

CWE-190 (Integer Overflow) in `decode_hq_slice_row()` in
`libavcodec/diracdec.c`. A crafted VC-2/Dirac media file with a large frame
size and 10-bit depth causes an integer overflow when computing a per-thread
buffer offset, resulting in an out-of-bounds (OOB) heap write.

## Root Cause

### Location
- **File**: `libavcodec/diracdec.c`
- **Overflow at**: line 923 — `&s->thread_buf[s->thread_buf_size * threadnr]`
- **Type declaration**: line 180 — `int thread_buf_size;`
- **Assignment**: line 962 — `s->thread_buf_size = coef_buf_size;`

### Mechanism

In `decode_lowdelay()` (lines 933–1045), the per-thread coefficient buffer
size is computed as an `int64_t`:

```c
coef_buf_size = subband_coeffs(s, s->num_x-1, s->num_y-1, 0, tmp) + 8;
coef_buf_size = (coef_buf_size << (1 + s->pshift)) + 512;    // line 957
```

For a 10-bit (pshift=1) frame large enough that `subband_coeffs` returns ~268 M
or more, `coef_buf_size` exceeds 1 073 741 823 (INT\_MAX/2).

At line 962, this `int64_t` value is assigned to the `int` field
`s->thread_buf_size`. The value still fits in `int` (it is below INT\_MAX), so
no truncation occurs here. However:

```c
s->thread_buf = av_realloc_f(s->thread_buf, avctx->thread_count,
                             s->thread_buf_size);   // line 963
```

This allocates `thread_count * thread_buf_size` bytes (a multi-GB buffer).

In `decode_hq_slice_row()` (line 923):

```c
uint8_t *thread_buf = &s->thread_buf[s->thread_buf_size * threadnr];
```

Both `s->thread_buf_size` and `threadnr` are signed 32-bit integers. When
`thread_buf_size > INT_MAX/2` and `threadnr >= 2`, the product overflows:

- `thread_buf_size ≈ 1 074 497 944`
- `threadnr = 2` (third decode thread)
- `1 074 497 944 * 2 = 2 148 995 888 > INT_MAX = 2 147 483 647` → **overflow**
- Signed result: `2 148 995 888 − 4 294 967 296 = −2 146 971 408` (negative!)
- `s->thread_buf + (−2 146 971 408)` → pointer **far before** the allocated buffer

This triggers an OOB heap write when `decode_hq_slice` then writes decoded
coefficients through `thread_buf`.

## Trigger Conditions

| Condition | Why | Value in PoC |
|---|---|---|
| bit\_depth = 10 | pshift=1, multiplies coef\_buf\_size by 4 | signal\_range index 3 |
| Frame ≥ 28 384×28 384 | Makes thread\_buf\_size > INT\_MAX/2 | 28 384×28 384 |
| num\_y ≥ 3 | Activates 3 decode threads (threadnr 0,1,2) | 3 |
| ≥ 3 decode threads | threadnr=2 triggers overflow | `-threads 4` |
| ~10 GB RAM | Allows large allocations before crash | System requirement |

## PoC Approach

The generator constructs a minimal but syntactically valid VC-2 bitstream:

1. **Sequence Header** (parse code 0x00): specifies 28 384×28 384 pixels,
   10-bit studio signal range (index 3 → YUV420P10), 4:2:0 chroma.

2. **HQ Intra Picture** (parse code 0xE8): specifies wavelet\_depth=4,
   num\_x=1, num\_y=3 (3 horizontal slice rows). Includes 3 minimal slice
   data entries (4 zero bytes each), just enough to pass the slice-count
   validation in `decode_lowdelay()` and reach the `execute2()` call.

3. **End of Sequence** (parse code 0x10): terminates the stream.

All integer fields in the sequence header and picture header use
Dirac interleaved exp-Golomb variable-length coding.

The VC-2 slice data content (all zeros) is intentionally garbage — the crash
occurs in pointer arithmetic *before* any actual slice decoding.

## Expected Outcomes

| Machine RAM | Outcome |
|---|---|
| < ~4 GB free | OOM in `alloc_sequence_buffers` (IDWT buffers) |
| 4–9 GB free | OOM in `av_realloc_f` for thread buffer (AVERROR(ENOMEM)) |
| ≥ ~10 GB free | Integer overflow → OOB heap write → crash or ASAN detection |

The `--demo` mode uses 16 640×16 640 with num\_y=3, which has a
thread\_buf\_size of ~369 MB — too small for the integer overflow, but
sufficient to demonstrate the code path being reached and the large
allocation being attempted (~1.1 GB for thread buffers).

## VC-2 Bitstream Format Summary

```
Parse Info (13 bytes): "BBCD" + parse_code(1) + next_offset(4) + prev_offset(4)
Sequence Header payload (variable): Dirac UE-Golomb encoded parameters
HQ Picture payload (variable):
  - picture_number (4 bytes, BE uint32)
  - wavelet_idx, wavelet_depth, num_x, num_y (UE-Golomb)
  - prefix_bytes, size_scaler (UE-Golomb, HQ-picture params)
  - quant_matrix flag (1 bit)
  - N minimal slice entries (4 zero bytes each)
End of Sequence (13 bytes, no payload)
```

## References

- `libavcodec/diracdec.c` lines 180, 918–926, 933–1009, 1051–1097
- `libavutil/slicethread.c` — confirms `threadnr` = per-thread index 0..nb\_active\_threads-1
- SMPTE ST 2042-1 (VC-2 specification)
