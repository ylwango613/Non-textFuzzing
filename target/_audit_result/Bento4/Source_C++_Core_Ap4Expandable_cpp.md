After exhaustive analysis, I've traced every relevant call chain through `Ap4Expandable.cpp` and all related code.

**Summary of findings:**

**`AP4_Expandable::Write()` (lines 87–101):** Stack buffer `bytes[8]` is indexed at `bytes[m_HeaderSize-2]` and the loop writes up to `m_HeaderSize-2` entries — both OOB if `m_HeaderSize > 9`. The `AP4_ASSERT(m_HeaderSize-1 <= 8)` guard is `#define AP4_ASSERT assert`, a no-op under `-DNDEBUG`. `m_HeaderSize` can be set to a large value by callers via `MinHeaderSize(large_payload)` in `AP4_ObjectDescriptor::AddSubDescriptor` and `AP4_IpmpDescriptor::SetData`. **However**, `Write()` is never called during mp42aac's read-only extraction path — mp42aac only writes raw ADTS bytes to the output stream, never `AP4_Expandable::Write()` on parsed descriptors.

**`AP4_UnknownDescriptor` (Ap4Descriptor.cpp:65-66):** `SetDataSize(payload_size)` return value is ignored; `payload_size` is file-controlled (up to 268 MB). Under standard C++ `new` throws `std::bad_alloc`, propagating as an exception — this is DoS, not memory corruption.

**`AP4_DecoderConfigDescriptor`/`AP4_EsDescriptor` substream size:** `payload_size - 13` / `payload_size - AP4_Size(offset-start)` can underflow producing a huge `AP4_SubStream` size, but `AP4_SubStream` reads are bounded by the underlying file stream — no heap corruption results.

**`AP4_DataBuffer::AppendData`:** Integer overflow (`existing_size + data_size`) → heap OOB, but `AppendData` is only called from MPEG-2 TS and HVCC code, not reachable from mp42aac's AAC extraction path.

No memory safety vulnerability in `Ap4Expandable.cpp` or its tightly coupled code is reachable via a crafted MP4 file passed to mp42aac.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
