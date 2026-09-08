The build uses `CONFIG_SAFE_BITSTREAM_READER=1`, meaning `UNCHECKED_BITSTREAM_READER=0` — `get_bits` clamps reads and won't go beyond `size_in_bits_plus8`. The buffer size check at line 45 has an integer-division imprecision for `width % 4 != 0`, but the resulting extra `get_bits` calls return clamped/zero values, and luma/cb/cr writes fall into alignment padding (linesize is always at least 16-byte aligned). No OOB write to the frame planes is reachable, and no heap allocation is involved in the decode path — only `ff_get_buffer` which has its own bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
