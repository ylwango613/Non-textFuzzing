# Vulnerability PoC Notes: NULL Dereference in vk_vp9_start_frame

## Status: SKIPPED

## Reason

Vulkan hardware acceleration is not available on this system. Running:

```
/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels 2>&1
```

produces an empty "Hardware acceleration methods:" section — no Vulkan device
is present. The vulnerability trigger path requires:

```
ffmpeg -hwaccel vulkan -i <crafted_vp9_file> -f null -
```

Without a Vulkan-capable GPU and the corresponding drivers/ICD loader
installed, FFmpeg cannot enter the Vulkan hwaccel code path at all, so the
vulnerable function `vk_vp9_start_frame()` is never called.

## Vulnerability Summary

- **File**: libavcodec/vulkan_vp9.c, lines 278-283
- **Function**: `vk_vp9_start_frame()`
- **CWE**: CWE-476 (NULL Pointer Dereference)

In the second reference-slot loop (lines 275-283), the pointer:

```c
hp = ref_frame->hwaccel_picture_private;   // line 278
```

is stored but the NULL guard at line 280 only checks `ref_frame->tf.f`.
If `hp` is NULL (Vulkan private data missing while an AVFrame exists), the
else-branch at line 283 unconditionally dereferences `hp->frame_id`, causing
a NULL pointer dereference.

## Trigger Conditions (all required)

1. VP9 inter-predicted frame referencing a prior frame.
2. FFmpeg launched with `-hwaccel vulkan` so the Vulkan decode path is active.
3. A reference frame where `tf.f != NULL` but `hwaccel_picture_private == NULL`
   — i.e., the AVFrame object exists but its Vulkan private data was never
   allocated or was freed early.

## Why Crafted File Alone Is Insufficient

The crafted media file controls the bitstream content (frame type, reference
frame indices, etc.) but cannot force the Vulkan runtime to omit allocation of
`hwaccel_picture_private`. Reaching the vulnerable state also requires either:

- The system to have a Vulkan device (so `-hwaccel vulkan` activates the path), AND
- A specific allocation failure or race condition within the Vulkan frame
  management code, OR a specially constructed sequence that leaves a reference
  slot populated at the AVFrame level but uninitialized at the Vulkan level.

Without Vulkan GPU hardware present, step 1 (activating the code path) is
impossible regardless of the crafted input file content.

## Environment

- FFmpeg binary: /data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
- Build: N-126435-gf93cd72dde with ASAN+UBSAN
- Platform: Linux 5.15.0-170-generic
- Vulkan available: NO (empty hwaccels list)
