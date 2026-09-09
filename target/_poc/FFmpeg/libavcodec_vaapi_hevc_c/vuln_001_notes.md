# VULN 001 - VAAPI HEVC tile column-width OOB heap write - SKIPPED

## Status: SKIPPED

## Reason

VAAPI hardware acceleration is not available on this system. The vulnerability requires
`-hwaccel vaapi` to exercise the code path in `vaapi_hevc_start_frame()`.

## Check Results

- `/dev/dri/` devices exist (card0, card1, card2, renderD128, renderD129) but `vainfo`
  failed or is not installed, indicating no working VAAPI driver/runtime is present.
- The pre-built FFmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`
  does not list `vaapi` among its supported hardware accelerators
  (`-hwaccels` output contained no vaapi entry).

## Vulnerability Summary

**VULN 001: VAAPI HEVC tile column-width OOB heap write**

- **Function**: `vaapi_hevc_start_frame()` in `libavcodec/vaapi_hevc.c`
- **Lines**: 220-221
- **CWE**: CWE-787 (Out-of-bounds Write)
- **Root cause**: The loop iterates up to `pps->num_tile_columns` (max 20) and writes
  into `pic_param->column_width_minus1[]`, which is declared as `uint16_t column_width_minus1[19]`
  in the VA-API struct `VAPictureParameterBufferHEVC`. With `num_tile_columns_minus1 = 19`
  (i.e., 20 columns) and a resolution of at least 1280 pixels wide (so `ctb_width >= 20`),
  the loop writes `column_width_minus1[19]` one element past the end of the array,
  producing a heap out-of-bounds write of 2 bytes.
- **Trigger**: Crafted HEVC file with `tiles_enabled_flag=1`, `uniform_spacing_flag=0`,
  `num_tile_columns_minus1=19`, and `pic_width_in_luma_samples >= 1280`.
- **Command**: `ffmpeg -hwaccel vaapi -i malicious.hevc -f null -`

## What Would Be Needed to Reproduce

1. A system with Intel or AMD GPU supporting VAAPI (e.g., Intel Quick Sync via i915 driver
   with libva-intel-driver or libva-intel-media-driver installed).
2. A working `vainfo` confirming VAEntrypointVLD for H.265/HEVC.
3. FFmpeg built with `--enable-vaapi`.
4. The crafted HEVC bitstream with the parameters described above.
