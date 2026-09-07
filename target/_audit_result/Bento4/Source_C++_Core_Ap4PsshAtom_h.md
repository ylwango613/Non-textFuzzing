**Group 1 analysis (Ap4PsshAtom.cpp lines 50–110): Parsing constructor and guards**

- `Create()` checks `size < AP4_FULL_ATOM_HEADER_SIZE` (12), then delegates to private ctor.
- Private ctor checks `size < AP4_FULL_ATOM_HEADER_SIZE + 20` (= 32) → early return if too small.
- Reads `m_SystemId` (16 bytes), then for version>0 reads `m_KidCount` (AP4_UI32).
- Guard at line 92: `m_KidCount > (size - 32)/16` → rejects and returns.
  - Maximum m_KidCount allowed: `(0xFFFFFFFF - 32)/16 = 268435453`.
  - `268435453 * 16 = 4294967248` — does NOT overflow AP4_UI32 (< 2^32). No under-allocation.
- `m_Kids.SetDataSize(m_KidCount*16)` and `stream.Read(..., m_KidCount*16)` — consistent size, no overflow.
- `data_size` bounded by `AP4_PSSH_MAX_DATA_SIZE = 16MB` at line 101.

**Group 2 analysis (lines 104–109): Padding computation and GetComputedSize()**

- `GetComputedSize()` = `12 + 16 + (version>0 ? 4+m_Kids.GetDataSize() : 0) + 4 + m_Data.GetDataSize() + m_Padding.GetDataSize()`.
- Theoretical overflow: `36 + m_KidCount*16 + data_size > 2^32` requires `m_KidCount ≥ 267387128`, forcing a ≥4.28 GB kids allocation that must succeed. Impractical (requires >4 GB RAM and actual file data).
- `m_Padding.SetDataSize(padding_size)` return value unchecked (line 107), but in C++ `new` throws `bad_alloc` on OOM rather than returning NULL, so no silent-NULL path leading to heap overflow.

**Group 3 analysis (lines 115–229): GetKid, SetKids, WriteFields, InspectFields**

- `GetKid()`: `index >= m_KidCount` guard prevents OOB in parsed atoms.
- `SetKids()` (API-level): `16*kid_count` could overflow AP4_UI32 if caller passes huge `kid_count`; but this is not triggered by file parsing (parsing path uses the ctor guard).
- `WriteFields()`: `m_KidCount*16` mirrors parser state — consistent.
- `InspectFields()`: loops `i < m_KidCount`, accesses `m_Kids.GetData()+(i*16)`. For parsed atoms m_Kids.GetDataSize() = m_KidCount*16, so in-bounds. Only unsafe if SetKids() was called with overflowing kid_count (API misuse, not file parsing).

**Group 4 analysis: DataBuffer failure modes**

- `ReallocateBuffer` uses `new AP4_Byte[size]` — throws `bad_alloc` on failure, never silently returns NULL. No path where `SetDataSize` succeeds but leaves buffer smaller than requested size. `m_DataSize` is only updated after successful allocation.

**Summary**: No practical heap buffer overflow or OOB write is reachable via crafted MP4 file input under normal memory conditions. The GetComputedSize() overflow requires >4 GB real heap; the guard at line 92 correctly prevents m_KidCount×16 overflow; data_size is bounded to 16 MB; all DataBuffer reads use the same size that was just allocated.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
