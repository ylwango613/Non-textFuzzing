# VULN 001: OOB Read in ff_els_decode_bit — Unbounded while-decrement Loop

## Vulnerability

**File**: `libavcodec/elsdec.c`, lines 338–339  
**Function**: `ff_els_decode_bit()`

The vulnerable code:
```c
while (pAllowable[ctx->j - 1] >= z)
    ctx->j--;
```

`pAllowable` points into `els_exp_tab[]` at offset 108 (`&els_exp_tab[ELS_JOTS_PER_BYTE * 3]`).  
`pAllowable[k]` is `uint32_t`, so when `z = 0` the condition `uint32_t >= 0` is always true.  
This causes unbounded decrement of `ctx->j`, reading before the start of `els_exp_tab[]`.

## Trigger Conditions

To reach the while loop with `z = 0`:
1. Enter LPS (less probable symbol) branch: `ctx->t <= ctx->x` after `ctx->t -= z`
2. `ctx->j + ALps <= 0` (import first byte from stream)
3. `ctx->j <= 0` after first import (import second byte from stream)
4. `z = pAllowable[ctx->j + ALps] = 0`, requiring `j + ALps <= -73`

## PoC Approach

A crafted AVI file is generated with the G2M4 video codec tag (standard container for G2M codec).  
The video frame contains:

1. **DISPLAY_INFO chunk**: Sets up a 64×64 frame with `COMPR_EPIC_J_B` (compression=2), 16×16 tiles
2. **TILE_DATA chunk**: Contains crafted ELS-encoded data

The ELS payload is initialized with `0xFF` bytes:
- First 3 bytes (`0xFF 0xFF 0xFF`) maximize `ctx->x = 0xFFFFFF`, biasing toward LPS
- Subsequent `0xFF` bytes are imported during decode, keeping `x` large
- This drives `j` deeply negative through repeated LPS events with large `|ALps|` values

The G2M decoder calls `ff_els_decoder_init()` then processes multiple ELS symbols
(`ff_els_decode_unsigned()` for transparent pixel R/G/B, then `epic_decode_tile()`
which calls `ff_els_decode_bit()` many times).

## File Structure

```
RIFF AVI
  LIST hdrl
    avih (main header: 64x64, 1 stream)
    LIST strl
      strh (vids/G2M4)
      strf (BITMAPINFOHEADER with G2M4 codec tag)
  LIST movi
    00dc (G2M4 frame = G2M4 magic + DISPLAY_INFO + TILE_DATA)
```
