# VULN 001 - SKIPPED

## Vulnerability Summary

**Function:** `nvdec_hevc_decode_slice()` in `libavcodec/nvdec_hevc.c`  
**Lines:** 282-295  
**Type:** Integer Overflow in bitstream accumulation leading to heap under-allocation and OOB write

## Reason for SKIP

### Primary Reason: NVDEC Not Available in FFmpeg Build

Running:
```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels
```

Output:
```
Hardware acceleration methods:
(empty)
```

The FFmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` was compiled **without NVDEC support**. The build configuration shows:
```
--disable-optimizations --disable-stripping --enable-debug=0 --disable-x86asm --disable-doc
```
There is no `--enable-nvdec` or `--enable-cuda-nvcc` flag in the configuration. NVDEC support requires the NVIDIA Video Codec SDK headers (`nvcuvid.h` etc.) to be present at build time.

### Secondary Reason: Impractical File Sizes

Even if NVDEC were available, triggering the integer overflow requires:
- At least two HEVC slices per frame, each with `raw_size` approaching `INT_MAX` (~2 GB)
- Total file size of 4 GB or more

The overflow occurs in the accumulation loop at lines 282-295 where `ctx->bitstream_len` (a 32-bit or size-limited value) wraps around when summing multiple slice sizes near `INT_MAX`. This makes a practical PoC extremely difficult to construct and run in a controlled test environment.

### Hardware Note

While NVIDIA GPU devices are physically present on this system (`/dev/nvidia0`, `/dev/nvidia1`), the FFmpeg binary was not compiled with NVDEC support, so the `-hwaccel nvdec` flag is not recognized and the vulnerable code path (`nvdec_hevc_decode_slice()`) is unreachable.

## Trigger Path

`ffmpeg -hwaccel nvdec -i <crafted.hevc> -f null -` → `nvdec_hevc_decode_slice()` (lines 282-295)

This path is **blocked** because NVDEC is absent from the FFmpeg build.
