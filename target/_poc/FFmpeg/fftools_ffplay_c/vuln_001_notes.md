# VULN 001 - Skipped

## Vulnerability
realloc_texture signed-integer overflow -> memset heap OOB write
- Function: realloc_texture() in fftools/ffplay.c (lines 840-861)
- Overflow at line 856: `pitch * new_height` where pitch is SDL_BYTESPERPIXEL * width

## Why Skipped

The ffplay binary does not exist at the expected path:
  /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffplay

This vulnerability is in `fftools/ffplay.c` which is the ffplay interactive media player.
The vulnerable code path requires:
1. The ffplay binary (SDL-based interactive player)
2. A running SDL display context (for SDL_CreateTexture / SDL_LockTexture)
3. The subtitle rendering pipeline in ffplay (subtitle_thread -> video_image_display -> realloc_texture)

The available binary at /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg is the
transcoding tool, which does not include the ffplay SDL rendering code. The vulnerable
function `realloc_texture()` is only compiled into the ffplay binary, not ffmpeg.

Therefore, this vulnerability cannot be triggered via `ffmpeg -i file -f null -` or any
other ffmpeg command-line invocation, and the PoC is skipped per the SKIP CONDITION.
