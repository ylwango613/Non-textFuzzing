# VULN 001: Stack Buffer Overflow in decodeMP3() via part2_3_length

## Vulnerability

**Function**: `decodeMP3()` in `mpglibDBL/interface.c`, line 618  
**CWE**: CWE-121 (Stack-based Buffer Overflow)

## Root Cause

In `decodeMP3()` for MPEG1 Layer3 stereo frames:

1. `wordpointer` is reset to `bsspace[bsnum] + 512` (line 556)
2. `copy_mp(mp, ssize=32, wordpointer)` copies 32-byte side info into `bsspace` (line 573)
3. `do_layer3_sideinfo()` calls `getbits()` internally, advancing the global `wordpointer` by 32 bytes → `wordpointer` now at `bsspace[bsnum] + 544`
4. `mp->dsize = (bits+7)/8` where `bits = do_layer3_sideinfo()` return value  
   = sum of `part2_3_length` fields across all granule×channel slots  
   With `part2_3_length = 4095` for all 4 slots: `dsize = (4×4095+7)/8 = 2048`
5. Check at line 614: `if(mp->dsize > mp->bsize)` — passes if bsize ≥ 2048
6. `copy_mp(mp, dsize=2048, wordpointer)` at line 618 writes 2048 bytes at offset 544
7. `bsspace[bsnum]` is `MAXFRAMESIZE+512 = 2304` bytes total; available from offset 544: **1760 bytes**
8. **Overflow: 2048 − 1760 = 288 bytes** past end of `bsspace[bsnum]`

## PoC Strategy

- Craft MPEG1 Layer3 Joint Stereo frames at 320kbps/44100Hz (frame size: 1044 bytes)
- Set all 4 `part2_3_length` fields to 4095 (0xFFF, the 12-bit maximum)
- Set `main_data_begin = 0` so no bit-reservoir backstep occurs
- Use 5 consecutive frames to accumulate `bsize ≥ 2048` by frame 2's decodeMP3 call:
  - Call 1 (frame 1): header parsed, returns MP3_NEED_MORE; bsize = 1040 after header
  - Call 2 (frame 2): 1044 more bytes added; bsize = 2084; ssize consumed → bsize=2052; dsize=2048 ≤ 2052 → overflow
- Frame header: `FF FB E0 64`
- Side info: 32 bytes with all four 12-bit `part2_3_length` fields = `0xFFF`

## ASAN Detection Limitation

The overflow is **confirmed by code analysis** but **not detected by ASAN** because:

- `MPSTR mp` is stack-allocated in mp3gain.c (line 1413)
- ASAN inserts red zones around stack *variables* but NOT between struct fields
- The 288-byte overflow writes into `hybrid_block[0][0][0..35]` (type `real=double`), which immediately follows `bsspace[2][2304]` in the MPSTR struct layout
- `hybrid_block[2][2][576]` = 18432 bytes — the 288-byte write is entirely within this field
- ASAN only triggers on writes to poisoned (red-zone) memory past the struct boundary

## Observed Effects

- Program runs to completion (exit code 0)
- `global_gain=127` is correctly decoded from crafted side info (confirms our side info IS parsed)
- Anomalous audio analysis result (64.82 dB recommendation for a silent/synthetic file)
- `hybrid_block` is corrupted with the frame's 0xAA payload bytes
- Corrupted doubles (0xAAAAAAAAAAAAAAAA ≈ 2.3×10¹⁹²) propagate through Layer 3 MDCT/synthesis
  but IEEE 754 float operations on large values produce Inf/NaN without crashing

## Key Constants

| Name                          | Value |
|-------------------------------|-------|
| `MAXFRAMESIZE`                | 1792  |
| `bsspace[bsnum]` size         | 2304  |
| `ssize` (MPEG1 stereo)        | 32    |
| `wordpointer` offset at write | 544   |
| `dsize` (crafted maximum)     | 2048  |
| Available bytes in bsspace    | 1760  |
| Overflow amount               | 288   |
| Overflow target               | `hybrid_block[0][0][0..35]` |
