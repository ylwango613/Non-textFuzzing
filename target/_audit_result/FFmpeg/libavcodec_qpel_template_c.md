**Analysis complete.**

`qpel_template.c` is a 222-line pure DSP computation template. It:

- Contains **no memory allocation** (`av_malloc`/`malloc`/`memcpy` are absent)
- Contains **no file/container parsing** — it operates exclusively on pre-allocated pixel frame buffers passed in by the codec machinery
- All pointer arithmetic uses `ptrdiff_t` strides that originate from frame dimensions validated upstream (not raw untrusted file bytes)
- The `h` (height) and stride parameters are validated by callers before reaching these functions
- The `+4` accesses in the 8-pixel-wide functions are safe because 8-pixel-wide buffers are guaranteed by the same codec path that guarantees `h` rows

None of the seven target vulnerability patterns (integer overflow → underalloc, extradata overflow, seek-table underalloc, OOB packet data, chunk-size overflow, stack buffer overflow, or pixel-format integer overflow) are present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
