# VULN-001 – Heap OOB Read via Integer Truncation in v210x decode_frame()

## Location

`FFmpeg/libavcodec/v210x.c`, function `decode_frame()`, line 48.

## Vulnerable Code

```c
if (avpkt->size < avctx->width * avctx->height * 8 / 3) {
    av_log(avctx, AV_LOG_ERROR, "Packet too small\n");
    return AVERROR_INVALIDDATA;
}
```

All operands are C `int`. Integer division truncates toward zero.

## Trigger Conditions

- `width = 2` (even; satisfies `decode_init` check)
- `height = 1081` (`height % 3 == 1`)
- `avpkt->size = floor(2 * 1081 * 8 / 3) = floor(17296 / 3) = 5765` bytes

### Why the check passes

```
check_threshold = 2 * 1081 * 8 / 3 = 5765   (integer division truncates 5765.33...)
avpkt->size     = 5765
condition       = 5765 < 5765  →  FALSE  (check passes, no early return)
```

### Why the decoder reads past the buffer

The decode loop processes rows in groups of 3, each group reading 4 × `uint32_t` = 16 bytes:

| Rows processed | Iterations | Bytes read |
|---------------|------------|------------|
| 1080 (full groups) | 360 | 360 × 16 = 5760 |
| 1 (last partial row) | 1 | 2 × 4 = 8 |
| **Total** | | **5768 bytes** |

The decoder performs `*src++` at line 71 (second read of the last partial iteration) targeting byte offsets **5764–5767**. The packet buffer is only 5765 bytes, so bytes **5765, 5766, 5767** are **out-of-bounds**.

## External Trigger Path

```
ffmpeg -vcodec v210x -i vuln_001_input.mov -f null -
```

The `-vcodec v210x` flag is required because the MOV demuxer maps the `v210` codec tag to `AV_CODEC_ID_V210` (the packed decoder), not `AV_CODEC_ID_V210X` (the vulnerable decoder). Forcing `-vcodec v210x` routes the packet to the vulnerable `v210x.c` decoder.

## Expected ASAN Output

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 4 at offset 5764 ...
  #0 decode_frame (.../v210x.c:71)
```

The OOB read is 3 bytes past the end of the allocated `AVPacket` data buffer (a 4-byte aligned read starting at offset 5764 in a 5765-byte buffer).

## CWE

CWE-125: Out-of-bounds Read
