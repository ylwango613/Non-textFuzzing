`AP4_FULL_ATOM_HEADER_SIZE = 12`. The mfro atom needs 12 + 4 = 16 bytes minimum, but `Create()` only checks `size >= 12`. If `size == 12..15`, the constructor calls `stream.ReadUI32(m_MfraSize)` reading beyond the atom boundary into the next atom's data — a stream over-read, but `ReadUI32` returns an error code (ignored) and `m_MfraSize` stays 0. No heap allocation, no `memcpy`, no array indexing involved.

The file is structurally minimal: one `AP4_UI32` member, one `stream.ReadUI32`, no `new[]`, no `malloc(count*size)`, no pointer arithmetic, no `AP4_Array`, no UAF surface. The ignored-return-value and off-by-4 size check are logic bugs, not memory-safety bugs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
