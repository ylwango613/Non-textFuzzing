# VULN-002 PoC Notes: decode_mad1_24() Case 12 OOB Write

## Vulnerability Summary

- **File**: `libavcodec/argo.c`
- **Function**: `decode_mad1_24()`
- **Lines**: ~451–550 (case 12 of the outer switch)
- **CWE**: CWE-787 Out-of-bounds Write

## Root Cause

`decode_mad1_24()` iterates over 4×4 blocks in **column-major** order (outer loop = x, inner loop = y). For each active block, it writes to 4 consecutive scanlines (`count = 0..3`, `dy = y + count`).

When `h = 10` (not divisible by 4), the last valid y-block is at `y = 8`. Iterating `count = 0..3` yields `dy = 8, 9, 10, 11`. Values `dy = 10` and `dy = 11` exceed the logical frame height (10), so the write:

```c
dst = (uint32_t *)frame->data[0] + pos + dy * l;
...
dst[0] = dst[-l];   // writes at logical row 10+ — OOB
```

is a **logical out-of-bounds write** past `frame->height`.

## Container Format

The Argo codec is not registered under any AVI/RIFF fourcc. The native container is **Argonaut BRP** (magic `BRPP`). FFmpeg auto-detects by content; the `.avi` extension is irrelevant and the `argo_brp` demuxer handles the file.

## Packet Construction

```
BRP file:
  FileHeader:  magic='BRPP', num_streams=1, byte_rate=1000
  StreamHeader: codec='BVID', id=0, duration=1000ms, extra_size=16
  BVID extra:  num_frames=1, width=8, height=10, depth=24

Frame packet (9 bytes):
  MAD1        → big-endian tag: 4D 41 44 31
  type=12     → 0x0C  (decode_mad1_24 case 12 OOB path)
  bitmap=0x04 → bit 2: activate block di=2 (x=0, y=8)
  codes=0x10  → bits[5:4]=01: count=2 gets code=1 (dy=10 OOB!)
  bcode=0x0A  → bits[1:0]=10: case-2 write loop (dst[0]=dst[-l])
  0xFF        → terminates outer while loop
```

## Execution Trace

```
bytestream state after reading 'MAD1' tag (4 bytes consumed):
  remaining: 0C 04 10 0A FF  (5 bytes)

decode_mad1_24:
  read type=0x0C (12)                   [4 bytes left]
  case 12:
    osize = ((10+3)/4)*((8+3)/4)+7 = 13
    osize>>3 = 1  (bitmap bytes)
    bits = gb->buffer  → points to 0x04
    skip(1)                              [3 bytes left]

  x=0, y=0 (di=0): bit0=0 → skip
  x=0, y=4 (di=1): bit1=0 → skip
  x=0, y=8 (di=2): bit2=1 → ACTIVE
    codes = get_byte() = 0x10            [2 bytes left]

    count=0: code=0 → skip; codes>>=2 → 0x04
    count=1: code=0 → skip; codes>>=2 → 0x01
    count=2: code=1                      dy=8+2=10  ← OOB!
      bcode = get_byte() = 0x0A          [1 byte left]
      dst = frame->data[0] + 0 + 10*l   ← logical row 10 (OOB)
      j=0: bcode&3=2 → dst[0]=dst[-l]   ← WRITE at row 10!
      j=1: bcode>>=2 → 2; dst[0]=dst[-l] ← WRITE at row 10!
    count=3: code=0 → skip

  x=4 blocks: all bits clear → skip

  read type=0xFF → return 0 (success)
```

## Why ASAN Does NOT Crash

`avcodec_align_dimensions2()` (libavcodec/utils.c line 312-316) applies:
```c
case AV_PIX_FMT_BGR0:
    if (s->codec_id == AV_CODEC_ID_ARGO) {
        w_align = 8;
        h_align = 8;   // ← height padded to multiple of 8!
    }
```

For `h=10`: `FFALIGN(10, 8) = 16`. The frame buffer is physically allocated for **16 rows**, not 10.

Additionally, `STRIDE_ALIGN = 64` (AVX-512 build) forces `linesize = 64` bytes (not 32).

Physical allocation:
- `size = linesize × h_aligned = 64 × 16 = 1024 bytes`
- Pool allocation = `1024 + 16 + 64 - 1 = 1103 bytes`

The OOB write at logical row 10 goes to byte offset `10 × 64 = 640`, which is well within the 1103-byte physical allocation. ASAN's heap shadow memory does not flag this.

**The vulnerability is a logical OOB (past `frame->height`) absorbed by alignment padding.**

This is consistent with the vulnerability being a real code defect (future allocators without padding, or different h_align values, or direct API use without alignment would expose it), but not triggering ASAN in the standard ffmpeg CLI environment.

## Expected vs Observed Behavior

| Metric | Value |
|--------|-------|
| File opened | Yes (`argo_brp` demuxer) |
| Codec initialized | Yes (w=8, h=10, BGR0) |
| Frame decoded | Yes (`frame= 1` in output) |
| Code path hit | Yes (case 12, block at y=8) |
| Logical OOB write | Yes (dy=10,11 > h=10) |
| ASAN crash | No (physical alloc covers rows 10-15) |

## Verdict

**VERIFIED_BEHAVIOR**: The vulnerable code path is confirmed triggered and the logical OOB writes execute, but the FFmpeg buffer allocator's 8-row height alignment prevents a physical heap overflow detectable by ASAN in this environment.
