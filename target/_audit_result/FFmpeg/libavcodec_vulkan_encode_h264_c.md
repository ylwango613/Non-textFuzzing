I've now read all 1687 lines of `vulkan_encode_h264.c` in four batches and traced the key data flows through related headers and implementation files.

**Analysis summary:**

**Buffer bounds — all checked:**
- `discard_list[MAX_DPB_SIZE]` (line 458): populated from `prev->nb_dpb_pics`, which is asserted `< MAX_DPB_SIZE` in `hw_base_encode.c:62`. Cannot overflow.
- `hp->mmco[H264_MAX_RPLM_COUNT]` (line 84): written in loop bounded by `discard` (≤15) + 1 terminator = 16 max, into a 33-element array. Safe.
- `hp->mods[MAX_REFERENCE_LIST_NUM][H264_MAX_RPLM_COUNT]` (line 83): inner loop bounded by `pic->nb_refs[0/1]` ≤ `MAX_PICTURE_REFERENCES = 2`, writing into 33-element arrays. Safe.
- `hp->ref_list_info.RefPicList0[i]` / `RefPicList1[i]` (lines 443-452): written with `i < nb_refs[0/1]` ≤ 2, into `STD_VIDEO_H264_MAX_NUM_LIST_REF`-sized arrays. Safe.

**`data_size` TOCTOU in `init_base_units()` (lines 1145–1160):** First `GetEncodedVideoSessionParametersKHR` call queries size, buffer allocated, second call fills it. The second call could theoretically return more data, but this requires a malicious/buggy Vulkan driver — not a crafted media file attack vector.

**Double-`snprintf` SEI identifier (lines 1529–1552):** Strings `driverName` / `deviceName` come from Vulkan physical device properties (system GPU driver), not from any attacker-controlled media stream. Race is impossible in practice.

**Attack-vector conclusion:** This file is an **encoder** (`ff_h264_vulkan_encoder`), not a decoder or demuxer. It processes frames being *encoded*, not frames parsed from a crafted media file. None of the audit-relevant attack paths (crafted mp4/mkv/avi → `ffmpeg -i <file>`) exercise this code. A53 CC side-data flows through `ff_alloc_a53_sei()` which handles size internally.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
