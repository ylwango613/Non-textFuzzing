# VULN-001: prores_aw Integer Overflow → Heap Buffer Overflow

## Vulnerability Summary
- **File**: libavcodec/proresenc_anatoliy.c (line 736)
- **Function**: prores_encode_frame()
- **Type**: Integer Overflow leading to Heap Buffer Overflow

## Root Cause
`frame_size` is computed as a 32-bit int:
```c
frame_size = FFALIGN(w,16) * FFALIGN(h,16) * 16 + 500 + FF_INPUT_BUFFER_MIN_SIZE;
```
When width=height=16384:
- `FFALIGN(16384,16) = 16384`
- `16384 * 16384 * 16 = 4,294,967,296 = 2^32`
- In 32-bit signed arithmetic this wraps to 0
- So `frame_size = 0 + 500 + 16384 = 16884`

`ff_alloc_packet` allocates only ~16KB, but `prores_encode_picture` then writes
`16384 * 16384 * 16 ≈ 4GB` of data into the tiny buffer → heap buffer overflow.

## PoC Approach
1. **gen.py** creates a minimal 16×16 yuv420p raw frame (384 bytes).
2. **run.sh** feeds it to ffmpeg with `-vf scale=16384:16384` to upscale to the
   overflow-triggering dimensions, then encodes with `-c:v prores_aw`.
3. ASAN (AddressSanitizer) is configured with `abort_on_error=0` so it logs the
   error rather than aborting immediately, capturing the heap-buffer-overflow report.

## Expected ASAN Output
```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
WRITE of size ... at 0x... thread T0
    #0 ... prores_encode_picture ...
    #1 ... prores_encode_frame ...
```
