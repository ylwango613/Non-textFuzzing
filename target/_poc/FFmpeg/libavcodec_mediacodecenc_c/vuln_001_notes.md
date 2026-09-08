# VULN 001 — SKIPPED

## Vulnerability
**Title:** Null Pointer Dereference in mediacodec_send — Unchecked getInputBuffer Return Value  
**File:** libavcodec/mediacodecenc.c, lines 826-827  
**CWE:** CWE-476 (NULL Pointer Dereference)

## Why Skipped

This vulnerability is **Android-specific** and cannot be triggered on a Linux host via the ffmpeg CLI.

### Technical Reasons

1. **MediaCodec is Android-only.**  
   `ff_AMediaCodec_getInputBuffer()` is implemented via Android JNI (`GetDirectBufferAddress`) or the Android NDK (`AMediaCodec_getInputBuffer`). Neither JNI nor NDK is present on a standard Linux system.

2. **h264_mediacodec encoder not compiled/available on Linux.**  
   Running:
   ```
   /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -encoders 2>/dev/null | grep mediacodec
   ```
   produces **no output**, confirming the MediaCodec encoder family is absent from this build.

3. **Trigger path requires Android runtime.**  
   The call chain `mediacodec_encode() → mediacodec_send() → ff_AMediaCodec_getInputBuffer()` cannot execute without an Android Dalvik/ART VM, a live `android.media.MediaCodec` Java object, and a functioning JNIEnv pointer — none of which exist on Linux.

4. **NULL return condition is JNI-internal.**  
   The NULL return from `getInputBuffer` arises when `GetDirectBufferAddress` receives a NULL or non-direct `ByteBuffer` from the Android MediaCodec Java layer. This internal JNI state is not reachable from a crafted media file on Linux.

## Conclusion

No PoC files (`_gen.py`, `_run.sh`) are generated. The vulnerability is real but requires an Android device or emulator with a working MediaCodec stack to reproduce.
