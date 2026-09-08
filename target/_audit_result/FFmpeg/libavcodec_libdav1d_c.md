After a complete read of all 621 lines of `libdav1d.c`, analysis of `libavutil/imgutils.c` for `av_image_get_buffer_size`, and targeted grep checks on all key call sites, here is my finding:

**Batch 1 (lines 1–200):** `libdav1d_parse_extradata` correctly validates `extradata_size >= 4` before using the buffer, and delegates actual AV1 OBU parsing to `dav1d_parse_sequence_header`. No unsafe indexing or size arithmetic found.

**Batch 2 (lines 77–123) — `libdav1d_picture_allocator`:** `av_image_get_buffer_size` has its own overflow guard (`if (sizes[i] > INT_MAX - ret) return AVERROR(EINVAL)`), so `ret` is always bounded. The subsequent `ret + DAV1D_PICTURE_ALIGNMENT * 2` add is also safe because dav1d constrains frame dimensions well below INT_MAX. The `pix_fmt[p->p.layout][p->seq_hdr->hbd]` index: `layout` is a validated enum (0-3), `hbd` is 0-2; both within the 4×3 array.

**Batch 3 (lines 278–353) — data wrapping:** Buffer ownership transfer via `pkt->buf = NULL` after `dav1d_data_wrap(..., pkt->buf)` is correct. The error path for `dav1d_data_wrap_user_data` failure calls `av_packet_free` (safe, since `pkt->buf` is already NULL) then `dav1d_data_unref` (calls `libdav1d_data_free` which unrefs the original `AVBufferRef`). No double-free or UAF.

**Batch 4 (lines 374–563) — `libdav1d_receive_frame`:** Film grain `memcpy` calls all use `sizeof()` of the *destination* field, which matches the struct layout. `p->m.user_data.data` is always set by the data wrapping path before dav1d consumes packets. The `av_assert0(data == opaque)` in `libdav1d_user_data_free` is a type-safe assertion (both sides are the same `pkt` pointer cast differently); no memory safety implication.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
