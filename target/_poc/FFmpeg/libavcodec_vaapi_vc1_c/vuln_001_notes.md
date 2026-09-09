# VULN 001 - Missing size>=4 Guard in vaapi_vc1_decode_slice - SKIPPED

## Reason for Skipping

The vulnerability in `vaapi_vc1_decode_slice()` (vaapi_vc1.c:480-483) is in the **VAAPI hardware acceleration path**, which is not available on this system.

## VAAPI Availability Check

Running `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels` produces:

```
Hardware acceleration methods:
(empty - no hwaccels listed)
```

VAAPI is not compiled in or not functional. The `vainfo` command is also not installed, and while `/dev/dri/` devices are present (card0, card1, card2, renderD128, renderD129), the FFmpeg build was compiled without VAAPI support (no `--enable-vaapi` in the build configuration).

## Why the Vulnerable Code Cannot Be Reached

1. The vulnerable function `vaapi_vc1_decode_slice()` is registered as the `decode_slice` callback only when VAAPI hardware acceleration is active. This happens in `vaapi_vc1_frame_params()` and the VAAPI init code, which requires a working VAAPI device context.

2. Without VAAPI, the `hwaccel->decode_slice` callback is never set to `vaapi_vc1_decode_slice`, so the code at lines 480-483 is never executed regardless of what media file is passed.

3. The trigger command requires `-hwaccel vaapi` flag. Without a VAAPI-capable GPU and driver stack, FFmpeg will reject the `-hwaccel vaapi` option or fall back to software decoding, bypassing `vaapi_vc1_decode_slice()` entirely.

## Vulnerability Summary (for reference)

- **Function**: `vaapi_vc1_decode_slice()` in `libavcodec/vaapi_vc1.c:480`
- **Bug**: `size -= 4` executed without checking `size >= 4` first, causing uint32_t underflow (wraps to 0xFFFFFFFF ~= 4 GB) when `size < 4` and `AV_RB32(buffer)` satisfies `IS_MARKER` check
- **CWE**: CWE-191 (Integer Underflow / Wraparound)
- **Impact**: ~4 GB value passed as `slice_size` to `ff_vaapi_decode_make_slice_buffer()` -> `vaCreateBuffer()`, potentially causing massive allocation or OOB access

## Conclusion

This vulnerability cannot be triggered on this system because VAAPI hardware acceleration is not available. The PoC would require a system with a VAAPI-capable GPU (e.g., Intel GPU with i965/iHD driver, AMD GPU with Mesa VAAPI driver) and appropriate kernel/driver support.
