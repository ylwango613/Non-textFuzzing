**Analysis complete.** Let me summarize what I checked across each code path in Ap4OhdrAtom.cpp:

**Stream-parsing constructor (lines 80–127):**
- `content_id_length`, `rights_issuer_url_length`, `textual_headers_length` are all `AP4_UI16` (max 65 535 each)
- `new char[length]` allocations: max 65 535, no integer overflow
- `AP4_String::Assign(buffer, size)` internally does `new char[m_Length+1]` where m_Length ≤ 65 535 → max 65 536. No overflow
- `bytes_used` at line 123: `12+1+1+8+2+2+2 + 65535*3 = 196 633` — fits comfortably in AP4_UI32

**InspectFields (lines 152–190):**
- `Reserve(1 + GetDataSize())`: GetDataSize() is at most 65 535 (bounded by AP4_UI16), so `1+65535 = 65536`. No overflow
- After Reserve(N+1) succeeds, SetData(data, N) runs without reallocation (N ≤ N+1 ≤ m_BufferSize)
- `textual_headers_string[N] = '\0'` writes into a buffer of capacity ≥ N+1. Within bounds

**WriteFields and Clone:** Both only serialize already-validated data. No external input paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
