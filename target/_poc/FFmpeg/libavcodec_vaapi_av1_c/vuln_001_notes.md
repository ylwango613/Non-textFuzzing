# VULN 001 – OOB Write in vaapi_av1_start_frame – Skip Reason

## Vulnerability Summary

An off-by-one OOB write exists in `vaapi_av1_start_frame()` at lines 302-309 of
`libavcodec/vaapi_av1.c`. When an AV1 bitstream specifies `tile_cols=64` or
`tile_rows=64`, the loops

```c
for (int i = 0; i < frame_header->tile_cols; i++)
    pic_param.width_in_sbs_minus_1[i] = ...;   // array size is 63

for (int i = 0; i < frame_header->tile_rows; i++)
    pic_param.height_in_sbs_minus_1[i] = ...;  // array size is 63
```

write one element past the end of the fixed-size `VAParameterBufferAV1`
array fields (declared with 63 elements each), causing a stack/heap buffer
overflow.

## Why This is SKIPPED

**VAAPI hardware acceleration is not compiled into the test binary.**

Verification:

```
$ /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels 2>&1
...
Hardware acceleration methods:
<empty>
```

The build configuration does not include `--enable-vaapi`. The build flags are:

```
--cc=gcc --cxx=g++ --extra-cflags='-fsanitize=address,undefined ...'
--disable-optimizations --disable-stripping --disable-x86asm --disable-doc
```

No `--enable-vaapi` or `--enable-libva` flag is present.

Although DRI render nodes (`/dev/dri/renderD128`, `renderD129`) are present on
the host, the ffmpeg binary was compiled without VAAPI support. Passing
`-hwaccel vaapi` to this binary results in "Hardware acceleration methods:" with
no entries, meaning the `-hwaccel vaapi` flag would be silently ignored or
rejected before ever reaching `vaapi_av1_start_frame()`.

The vulnerable code in `libavcodec/vaapi_av1.c` is therefore dead code in this
binary and cannot be reached by any malformed media file passed on the command
line.

## What Would Be Needed to Trigger

1. An ffmpeg binary compiled with `--enable-vaapi` (requires `libva-dev`).
2. A functioning VAAPI-capable GPU driver (e.g., Intel i965, iHD, AMD radeonsi).
3. An AV1 IVF file with `tile_cols_log2=6` (giving `tile_cols=64`) in the
   sequence or frame header tile info OBU.

Under those conditions, the `vaapi_av1_start_frame()` function would be invoked
and the OOB write at `pic_param.width_in_sbs_minus_1[63]` would be accessible.
