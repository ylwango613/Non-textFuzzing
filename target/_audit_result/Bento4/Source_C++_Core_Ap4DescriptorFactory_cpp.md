Based on my exhaustive analysis of `Ap4DescriptorFactory.cpp` and every descriptor constructor it calls, let me confirm the key math for the clamping behavior before concluding.

**Group 1 — Factory itself (lines 44–134):** The `payload_size` accumulation loop (lines 66–78) decodes at most 4 × 7-bit = 28 bits, capping `payload_size` at `0x0FFFFFFF` = 268 MB. The final seek (`offset+header_size+payload_size`, line 131) uses 64-bit `AP4_Position` arithmetic — no overflow.

**Group 2 — Unsigned underflows in substream size (DecoderConfigDescriptor line 92, EsDescriptor line 103, ObjectDescriptor line 96, InitialObjectDescriptor line 254–255):** When `payload_size < N` (e.g., < 13 for DecoderConfig), `payload_size - N` wraps to ~4 GB as `AP4_UI32`, then promotes to 64-bit `AP4_LargeSize` = 4,294,967,283. Critical check: in `AP4_SubStream::ReadPartial` line 447, the clamped value is `(AP4_Size)(m_Size - m_Position)`. Since clamping only triggers when `m_Position + bytes_to_read > m_Size`, we always have `m_Size - m_Position < bytes_to_read` (= the buffer's allocated size). The 32-bit truncation of `m_Size - m_Position` never exceeds the allocated buffer because `m_Size` itself fits in 32 bits (= 4,294,967,283 < 2^32). Result: OOB file-data reads bounded by actual file content, but no heap corruption. `AP4_SubStream::Seek` correctly rejects positions beyond `m_Size`, preventing infinite loops.

**Group 3 — `AP4_UnknownDescriptor` / `AP4_DecoderSpecificInfoDescriptor` allocations:** `SetDataSize(payload_size)` allocates exactly `payload_size` bytes; `stream.Read(..., payload_size)` writes at most `payload_size` bytes. Allocation and read sizes always match. DoS via OOM (up to 268 MB), not heap overflow.

**Group 4 — `AP4_IpmpDescriptor` fields_size accounting (Ap4Ipmp.cpp lines 130–140):** `fields_size = 6/7` omits the 16-byte `m_ToolId`, causing allocation of `payload_size - 6` instead of `payload_size - 22`, reading 16 extra bytes of adjacent file data. OOB file-data read — not a heap overflow.

**Group 5 — `AP4_DecoderSpecificInfoDescriptor::Inspect` (line 94):** `new char[m_Info.GetDataSize()*3+1]` — at max `0x0FFFFFFF * 3 + 1 = 0x2FFFFFFE`, no 32-bit overflow. Inspect is not called during `mp42aac` parsing.

**Conclusion:** All identified issues are either logic bugs causing reads beyond declared descriptor boundaries (bounded by actual file data), DoS via large allocations, or the `fields_size` miscalculation causing adjacent file-data reads. None constitute heap overflow, UAF, OOB write, or stack overflow that could enable memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
