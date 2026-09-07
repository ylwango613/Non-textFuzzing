After thorough multi-pass reading of `dump_xml.c`, `amf.c`, `flv.c`, `info.c`, `update.c`, `avc.c`, and `bitstream.c`, here is my complete analysis:

**Group 1 — dump_xml.c (lines 1–307):**
- `ns_decl[50]` + `sprintf(ns_decl, " xmlns%s=\"http://schemas.flvmeta.org/AMF0/1.0/\"", ns)` at line 54: maximum output is ` xmlnsamf:="http://schemas.flvmeta.org/AMF0/1.0/"` = 49 chars + null = 50 bytes. Exactly fits; not an overflow. `ns` is code-controlled, never file-controlled.
- All `printf`/`puts` outputs use file-supplied strings only through `%s` or `%.*s` with explicit length, not as format strings. No format-string vulnerability.
- Recursive `xml_amf_data_dump` with `indent_level+1`/`+2`: bounded by file parse depth; `int` overflow at ~10^9 nesting levels is physically unreachable.

**Group 2 — amf.c (malloc/calloc paths):**
- `amf_string_read`: `strsize` is `uint16_t` (max 65535); `calloc(strsize, 1)` and `calloc(size+1, 1)` (where `size+1` is computed as `int`, giving max 65536) are safe on all platforms.
- `amf_array_read`: `array_size` is `uint32` but loop exits on EOF via `amf_data_read` returning an error; no pre-allocation of `array_size` elements; no heap overflow.
- All other malloc calls use fixed struct sizes.

**Group 3 — update.c `write_flv`:**
- `malloc(info->biggest_tag_body_size + FLV_TAG_SIZE)` at line 103: `biggest_tag_body_size` is bounded by `uint24_be` max = 16,777,215; `FLV_TAG_SIZE=11`; no integer overflow on 32-bit or 64-bit. Missing null-check after malloc, but OOM failure is not controllable by crafted file content.

**Group 4 — avc.c `read_avc_resolution`:**
- `body_length - sizeof(flv_video_tag)` can underflow if `body_length < sizeof(flv_video_tag)`, bypassing the SPS-size bounds check. However, all subsequent reads go through `flv_read_tag_body` which is bounded by `current_tag_body_length`. If fewer bytes remain, reads return 0 and the function exits via `FLV_ERROR_EOF`. `malloc((size_t)sps_size)` where `sps_size` is `uint16` (max 65535) is safe.

**Group 5 — bitstream.c:**
- `skip_bits` can advance `bb->current` without bounds; `get_bit` has a `bb->current - bb->start > bb->size - 1` guard that returns -1 on OOB before any dereference.

**Group 6 — `amf_object_delete` null-pointer dereference:**
- Bug exists (advances `node = node->next` without null check then dereferences `node->data`), but `amf_object_delete` and `amf_associative_array_delete` have zero call sites in the entire codebase outside their own definition—not reachable from any user input path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
