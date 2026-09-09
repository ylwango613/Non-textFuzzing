Analysis complete. Summary of findings across `raw.c` (95 lines):

- `avcodec_pix_fmt_to_codec_tag()`: walks `raw_pix_fmt_tags` with `pix_fmt >= 0` guard. Table is properly terminated with `{ AV_PIX_FMT_NONE, 0 }` (NONE = -1). Safe.
- `find_pix_fmt()`: walks with `pix_fmt != AV_PIX_FMT_NONE`. Same properly-terminated tables. Safe.
- `avpriv_pix_fmt_find()`: switch without `default` leaves `tags` uninitialized for out-of-range enum values — but every call site passes a compile-time enum constant (`PIX_FMT_LIST_RAW/AVI/MOV`), none derive the `list` argument from file data.
- `fourcc` in lookups can come from container data (e.g., `avctx->codec_tag`), but a malicious fourcc just causes the loop to exhaust the fixed static table and return `AV_PIX_FMT_NONE` — no OOB is possible.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
