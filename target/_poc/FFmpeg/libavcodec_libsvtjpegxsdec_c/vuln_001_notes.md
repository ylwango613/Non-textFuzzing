# VULN-001 Notes — Double-Close of SVT Decoder Context After Re-init Failure

## Status: SKIPPED

## Reason: libsvtjpegxs Decoder Not Available in Binary

The vulnerable code lives in `libavcodec/libsvtjpegxsdec.c`, which implements the
`libsvtjpegxs` decoder — a wrapper around the Intel SVT-JPEG-XS library
(`libSvtJpegXs`).

### Skip Condition Check

```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders 2>/dev/null | grep -i jpegxs
```

Output: `..VILS jpegxs   JPEG XS`  — only the generic (non-SVT) JPEG XS codec appears.

```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -decoders 2>/dev/null | grep -i libsvt
```

Output: (empty) — `libsvtjpegxs` decoder is absent.

`build_test/config.h` contains `#define CONFIG_LIBSVTJPEGXS 0`, confirming the
SVT library was not linked at build time.

### Vulnerability Summary (for reference)

- **CWE-415 Double Free / Double Close**
- In `svt_jpegxs_dec_decode()` (lines 119-128): when a second frame with
  different dimensions/format triggers the re-init path, `decoder_initialized`
  is already 1, so `svt_jpeg_xs_decoder_close()` is called (line 122).  If
  `svt_jpeg_xs_decoder_init()` then fails (line 123-128), the function returns
  an error WITHOUT clearing `decoder_initialized`.
- In `svt_jpegxs_dec_free()` (line 186): `svt_jpeg_xs_decoder_close()` is
  always called unconditionally, regardless of whether `decoder_initialized` is
  set.  This produces a second close of an already-closed (and potentially
  freed) decoder handle, leading to a double-free.

### How to Re-enable Triggering

Rebuild FFmpeg with the SVT-JPEG-XS library:

```bash
# Install libsvtjpegxs-dev (or build from https://github.com/OpenVisualCloud/SVT-JPEG-XS)
./configure --enable-libsvtjpegxs ...
make -j$(nproc)
```

Then a two-packet raw JPEG XS input where packet 1 decodes cleanly and packet 2
carries a different width/height and a header that passes
`svt_jpeg_xs_decoder_get_single_frame_size_with_proxy` but causes
`svt_jpeg_xs_decoder_init` to fail would trigger the bug.
