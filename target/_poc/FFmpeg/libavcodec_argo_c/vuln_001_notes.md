# VULN 001 PoC Notes: decode_mad1() case-8 OOB Write

## Vulnerability Summary

**File**: `libavcodec/argo.c`
**Function**: `decode_mad1()`
**Lines**: 159–173
**CWE**: CWE-787 (Out-of-bounds Write)

The outer loop iterates `for (int y = 0; y < h; y += 8)`, which only requires `y < h`
rather than `y + 8 <= h`. When the frame height is not a multiple of 8 (e.g., `h=10`),
the final iteration at `y=8` has only 2 valid rows (rows 8 and 9), but the inner loop
always writes exactly 8 rows via `memset`, overflowing the frame buffer by up to
`7 * linesize[0]` bytes.

## Trigger Conditions

- AVI container file (or BRP)
- Argo codec (`AV_CODEC_ID_ARGO`)
- `bits_per_coded_sample = 8` → `biBitCount=8` in BITMAPINFOHEADER → PAL8 mode
- Frame `height = 10` (even, passes the `width%2 || height%2` guard in `decode_init`,
  but not a multiple of 8)
- Frame `width = 8` (divisible by 8, so one 8×8 block per row of blocks)
- Frame data: `MAD1` magic + `0x08` (type=8 block) + fill bytes

## Root Cause

```c
// argo.c lines 161-173
for (int y = 0; y < h; y += 8) {         // BUG: should be y + 8 <= h
    for (int x = 0; x < w; x += 8) {
        int fill = bytestream2_get_byte(gb);
        uint8_t *ddst = dst + x;
        for (int by = 0; by < 8; by++) {  // always writes 8 rows
            memset(ddst, fill, 8);
            ddst += l;                     // OOB when y=8, by >= 2 (rows 10-15)
        }
    }
    dst += 8 * l;
}
```

For `h=10`, `w=8`:
- Iteration `y=0`: block at `(x=0)` fills rows 0–7 (valid)
- Iteration `y=8`: block at `(x=0)` fills rows 8–15 (rows 10–15 are OOB)

The frame buffer for PAL8 mode holds `linesize × height` bytes (no extra 8-row alignment
padding for PAL8, unlike BGR8/BGR0 which do get `h_align=8` in `utils.c`), so rows 10–15
lie beyond the allocation boundary, detected by ASAN as a heap-buffer-overflow.

## File Structure

The AVI file (`vuln_001_input.avi`) contains:
- `RIFF 'AVI '` container
- `hdrl` list with `avih` (width=8, height=10) and `strl/strh/strf`
- `strf` BITMAPINFOHEADER: `biWidth=8`, `biHeight=10`, `biBitCount=8`,
  `biCompression='Argo'` (fourcc `0x6F677241`)
- One video frame `00dc`: `MAD1\x08\x41\x41\xFF` (8 bytes)

## Invocation

Because there is no standard AVI RIFF fourcc mapping for `AV_CODEC_ID_ARGO`,
the codec is forced explicitly:

```bash
ffmpeg -vcodec argo -i vuln_001_input.avi -f null -
```

`avformat_open_input()` parses the AVI and reads `biWidth=8`, `biHeight=10`,
`biBitCount=8` from the BITMAPINFOHEADER. The forced `-vcodec argo` codec is
initialized with these parameters: `bits_per_coded_sample=8` → PAL8 mode.
`decode_init()` passes all sanity checks (both dimensions are even).
`avcodec_send_packet()` delivers the frame payload → `decode_frame()` sees
the `MAD1` tag → calls `decode_mad1()` → case 8 triggers the OOB write.

## Expected Behavior

With ASAN-instrumented ffmpeg:
- ASAN detects a heap-buffer-overflow write at `ffmpeg/libavcodec/argo.c:167`
  (the `memset(ddst, fill, 8)` call when `ddst` points beyond the frame buffer)
- Error report: `heap-buffer-overflow on address ... WRITE of size 8`
- Shadow bytes show the red zone or unallocated region after the frame allocation

## Fix

Replace the outer loop condition with a proper partial-block guard (mirroring
the correct `y + 12 <= h` check already present in `decode_mad1_24()` case 8):

```c
- for (int y = 0; y < h; y += 8) {
+ for (int y = 0; y + 8 <= h; y += 8) {
```
