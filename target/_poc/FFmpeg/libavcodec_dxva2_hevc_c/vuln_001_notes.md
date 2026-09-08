# VULN 001 – OOB Heap Write via Tile Column/Row Array Overflow in DXVA2 HEVC HW Decoder

## Status: SKIPPED

## Reason

This vulnerability is **not triggerable** on the current system because:

1. **DXVA2 is a Windows-only API.**  
   DXVA2 (DirectX Video Acceleration 2) is part of the Microsoft DirectX stack and is only available on Windows. It cannot be loaded, initialized, or exercised on a Linux host.

2. **The current system is Linux.**  
   Confirmed via `uname -s` → `Linux`.

3. **The ffmpeg binary does not expose dxva2 as a hwaccel.**  
   Running `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels 2>&1 | grep -i dxva` produced no output, confirming that the binary was not compiled with DXVA2 support and the hardware acceleration context required to reach `ff_dxva2_hevc_fill_picture_parameters()` cannot be created.

4. **The vulnerable code path requires an active DXVA2/D3D11VA hwaccel context.**  
   `ff_dxva2_hevc_fill_picture_parameters()` (lines 149-154 of `libavcodec/dxva2_hevc.c`) is only called from within the DXVA2 or D3D11VA decoder callback chain. Without a working hwaccel context the function is never reached, regardless of how the input HEVC bitstream is crafted.

## Trigger Path (Windows-only)

```
ffmpeg -i <crafted.hevc> -hwaccel dxva2 -f null -
```

A crafted HEVC SPS with `tiles_enabled_flag=1`, `uniform_spacing_flag=0`, and
`num_tile_columns_minus1 >= 19` (i.e., 20+ tile columns) would cause
`ff_dxva2_hevc_fill_picture_parameters()` to write up to
`20 * sizeof(USHORT)` bytes past the end of the fixed-size 20-element
`column_width_minus1` / `row_height_minus1` arrays in the
`DXVA_PicParams_HEVC` structure, constituting a heap out-of-bounds write.

## Conclusion

Because DXVA2 is unavailable on Linux, no proof-of-concept file can trigger
this vulnerability on the current system. The finding should be evaluated on a
Windows host with a DXVA2-capable GPU and a Windows build of FFmpeg.
