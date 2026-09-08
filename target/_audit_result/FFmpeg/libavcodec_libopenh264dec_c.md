I've now thoroughly analyzed the full code path:

1. **File read**: All 192 lines of `libopenh264dec.c` read and analyzed.
2. **`image_copy_plane`** (imgutils.c:344-357): Checks `if (!dst || !src) return;` — NULL ptrs[i] are safe. The `av_assert0` guards on stride ≥ bytewidth are only in debug builds; in release, a stride < width would cause OOB reads, but that depends entirely on libopenh264 returning inconsistent `iStride`/`iWidth` — a library-side bug, not FFmpeg's.
3. **`ff_set_dimensions`** (utils.c:91-104): Validates width/height via `av_image_check_size2`, caps them to 0 on failure. Return value is checked at line 148.
4. **`ff_get_buffer`**: Uses the validated `avctx->width`/`avctx->height` for allocation.
5. **`av_image_copy2`**: Copies using source strides from libopenh264, destination strides from the allocated frame. Source strides are libopenh264 internals; no FFmpeg-level overflow path exists independent of libopenh264 returning malformed data.
6. **Flush/reinit**: OOM after `svc_decode_init` failure in `svc_decode_flush` is properly guarded at line 113.

No independently-triggerable memory safety vulnerabilities exist purely within FFmpeg's code in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
