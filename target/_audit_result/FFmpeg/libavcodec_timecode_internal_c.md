The analysis is complete. `libavcodec/timecode_internal.c` is a one-line shim that includes `libavutil/timecode_internal.c`. That file contains only two functions:

- `bcd2uint()` — pure arithmetic, no memory operations.
- `ff_timecode_set_smpte()` — writes only to caller-supplied `unsigned *` pointers that every call site initializes as addresses of local stack variables. No allocation, no buffer copy, no size arithmetic that could overflow.

All callers (`av_timecode_make_smpte_tc_string2`, `put_timecode_fields`, `nvenc.c`) pass addresses of local variables — no NULL dereference risk. The shift `*ff <<= 1` produces at most 78 (BCD nibbles capped to 0–9), well within `unsigned` range.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
