Based on my complete analysis of `evc_parser.c` and its full call chain (`evc_parse.c`, `evc_ps.c`, `evc_parse.h`, `evc_ps.h`, `evc.h`), here is a summary of what I checked:

**`nalu_size` signed/unsigned confusion** (lines 229–252): `evc_read_nal_unit_length` returns `uint32_t` assigned to `int nalu_size`. Values > INT_MAX wrap to negative, bypassing the `data_size < nalu_size` guard. However, `parse_nal_unit` has a secondary `buf_size <= 0` check that catches all negative values before any dangerous operation — no memory corruption reachable.

**`chroma_format_idc` array index** (line 174): Index into 4-element `pix_fmts_*` tables. Validated to ≤ 3 in `ff_evc_parse_sps` (line 183 of `evc_ps.c`). Safe.

**`slice_pic_parameter_set_id` / `pps_seq_parameter_set_id` OOB**: `ff_evc_parse_slice_header` validates `slice_pic_parameter_set_id < EVC_MAX_PPS_COUNT` and returns error for NULL pps/sps before storing the ID. `ff_evc_parse_pps` validates `pps_seq_parameter_set_id < EVC_MAX_SPS_COUNT`. Safe.

**NULL check ordering in `decode_extradata`** (line 266–268): `bytestream2_init` is called before the `data == NULL` check. The only call site in `evc_parse` guards with `avctx->extradata &&`, so NULL is never passed in practice. Not exploitable via current paths.

**Crop offset underflow** (lines 133–135): `pic_width - crop_left - crop_right` computed in `uint32_t` and stored in `int s->width`. Could be negative/huge, but these are informational metadata fields not used for memory allocation in this file.

**No attacker-controlled allocation sizes**: All `av_mallocz` calls in the call chain use fixed `sizeof(*sps)`/`sizeof(*pps)`, never attacker-controlled lengths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
