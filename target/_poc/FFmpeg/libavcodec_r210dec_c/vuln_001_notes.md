# VULN-001: Integer Overflow in r210dec decode_frame() — PoC Notes

## Vulnerability Summary

**File**: `libavcodec/r210dec.c`, function `decode_frame()`, lines 51-54  
**CWE**: CWE-190 (Integer Overflow) → CWE-125 (Out-of-Bounds Read)

## Root Cause

At line 51 of `r210dec.c`:

```c
int aligned_width = FFALIGN(avctx->width,
                            avctx->codec_id == AV_CODEC_ID_R10K ? 1 : 64);
// ...
if (avpkt->size < 4 * aligned_width * avctx->height) {
```

The expression `4 * aligned_width * avctx->height` uses signed 32-bit arithmetic. With
`width=23170`, `height=23170`:

- `aligned_width = FFALIGN(23170, 64) = 23232`
- `4 * 23232 * 23170 = 2,153,141,760`
- `INT_MAX = 2,147,483,647`
- The multiplication **overflows** 32-bit signed int, yielding a negative value (~`-141,825,536`)

Since `avpkt->size` (4 bytes) is never less than a negative number, the size guard is
**bypassed entirely**.

## Trigger Path

```
ffmpeg -i crafted.avi -f null -
  -> avformat_open_input()      [parses AVI, extracts R210 stream with 23170x23170]
  -> avcodec_send_packet()      [sends 4-byte frame packet]
  -> decode_frame()             [r210dec.c]
     -> aligned_width = 23232
     -> size check: 4 < (negative) -> FALSE -> bypassed
     -> ff_get_buffer()         [tries to allocate ~3.2 GB GBRP10 frame]
     -> if allocation succeeds: decode loop reads width*height*4 bytes from
        avpkt->data (only 4 bytes allocated) -> HEAP OOB READ
```

## Expected Behavior

1. **If ASAN + UBSAN built**: UBSAN fires on the signed integer overflow at line 51 
   (`signed integer overflow: 4 * 23232 * 23170 cannot be represented in type 'int'`).

2. **If ff_get_buffer fails** (likely on systems with <4 GB free): function returns
   `AVERROR(ENOMEM)` before the OOB read loop is reached. The integer overflow still
   occurs but its downstream effect (OOB read) is blocked.

3. **If ff_get_buffer succeeds** (~3.2 GB GBRP10 frame allocated): the decode loop
   reads `23170 * 23170 * 4 = ~2.1 GB` from a 4-byte buffer — massive heap OOB read,
   caught by ASAN as `heap-buffer-overflow`.

## PoC Files

- `vuln_001_gen.py`: Generates `vuln_001_input.avi` — a minimal AVI with R210 stream,
  width=23170, height=23170, and only 4 bytes of actual frame data.
- `vuln_001_run.sh`: Runs ffmpeg with ASAN options and collects output.

## Limitations

The primary practical limitation is memory: decoding a 23170x23170 GBRP10 frame
requires ~3.2 GB. On memory-constrained systems `ff_get_buffer` will fail (ENOMEM),
preventing the OOB read in the decode loop. The integer overflow itself (and the
bypassed size check) still occurs regardless. UBSAN-enabled builds will report the
overflow at compile time or at runtime regardless of memory availability.
