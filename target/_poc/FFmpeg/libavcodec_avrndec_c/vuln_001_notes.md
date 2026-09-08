# PoC Notes: OOB Heap Read in AVRN Interlaced Decode Path

## Vulnerability

- **File**: `libavcodec/avrndec.c`
- **Function**: `decode_frame()`
- **Lines**: 71–77
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

In the interlaced decode path, the second `memcpy` on line 75:

```c
memcpy(p->data[0] + (y+!a->tff)*p->linesize[0],
       buf + avctx->width*true_height+4,
       2*avctx->width);
```

reads from `buf + width*true_height + 4`. As the loop advances `buf` by `2*width` each iteration, in the last iteration (`j = height/2 - 1`, i.e. `y = height-2`), the read ends at:

```
initial_buf + (height/2 - 1)*2*width + width*true_height + 4 + 2*width
= initial_buf + (height - 2)*width + width*height + 4 + 2*width
= initial_buf + width*(height + height - 2 + 2) + 4
= initial_buf + 2*width*height + 4
= initial_buf + buf_size + 4     (when buf_size == 2*width*height exactly)
```

This reads **4 bytes past the end** of the packet buffer.

## Trigger Conditions

1. **Interlace mode enabled**: extradata in STRF chunk must satisfy:
   - `extradata_size >= 9`
   - `extradata[4]+28 < extradata_size`
   - `memcmp(extradata + extradata[4]+4, "1:1(", 4) == 0`

2. **Exact packet size**: `buf_size = 2 * width * height` (minimum accepted)
   - This ensures `true_height = height` and the remainder `R = 0`

3. **Small even height**: height=4 makes the last iteration index obvious

## Crafted AVI Structure

- Format: RIFF AVI
- Codec: AVRN (FourCC = `AVRN`)
- Width: 100, Height: 4
- Extradata (37 bytes):
  - `[4] = 5` (offset byte, so ndx = 9)
  - `[9..12] = "1:1("` (triggers interlace)
  - `[33] = 0` (tff = 0)
- Single video frame: exactly 800 bytes (= 2*100*4)

## Concrete OOB Proof

With width=100, height=4, buf_size=800:
- `true_height = 800 / 200 = 4`
- `buf` adjusted by `(4-4)*100 = 0` (no change)
- Iteration y=0: second memcpy reads buf[404..603] — OK
- Iteration y=2: buf advances to +200; second memcpy reads buf[604..803]
  - Valid range: [0, 799]
  - **Bytes 800–803 are OOB** (4 bytes past end)

## Detection

When FFmpeg is built with AddressSanitizer (`-fsanitize=address`), this triggers a `heap-buffer-overflow` report at the second memcpy in the last loop iteration.
