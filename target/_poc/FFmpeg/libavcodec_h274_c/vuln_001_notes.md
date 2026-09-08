# Vulnerability 001 - SKIPPED

## Vulnerability
Use-After-Free in `ff_h274_hash_freep()` (libavcodec/h274.c, lines 916-927)

## Why Skipped

The vulnerable code path exists exclusively inside a `#if HAVE_BIGENDIAN` preprocessor branch in `libavcodec/h274.c`. This branch is only compiled on big-endian platforms (e.g., MIPS, PowerPC, s390x).

The target binary:
- Path: `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg`
- Architecture: `ELF 64-bit LSB pie executable, x86-64` (little-endian)
- Build config: `HAVE_BIGENDIAN=0` (confirmed via `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/config.h`)

Because `HAVE_BIGENDIAN` is 0, the `#if HAVE_BIGENDIAN` branch containing the UAF code was never compiled into the binary. The vulnerable code simply does not exist in this build.

## Trigger Path (would apply on big-endian build)
```
ffmpeg -i <crafted.vvc> -f null -
  -> avcodec_close()
    -> ff_h274_hash_freep()
      -> UAF inside #if HAVE_BIGENDIAN block
```

## Conclusion
This PoC cannot be triggered by passing a crafted media file to this ffmpeg binary on a little-endian (x86-64) host. A big-endian build is required to exercise this code path.
