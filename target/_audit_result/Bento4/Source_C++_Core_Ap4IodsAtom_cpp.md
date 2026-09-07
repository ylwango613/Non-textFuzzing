After a thorough multi-pass analysis of `Ap4IodsAtom.cpp` and its full transitive dependency chain (`Ap4DescriptorFactory.cpp`, `Ap4ObjectDescriptor.cpp`, `Ap4EsDescriptor.cpp`, `Ap4DecoderConfigDescriptor.cpp`, `Ap4DecoderSpecificInfoDescriptor.cpp`, `Ap4Descriptor.cpp`, `Ap4Ipmp.cpp`, `Ap4DataBuffer.cpp`, `Ap4ByteStream.cpp`):

**Group 1 — URL stack buffers** (`Ap4ObjectDescriptor.cpp:86-89`, `Ap4ObjectDescriptor.cpp:236-242`, `Ap4EsDescriptor.cpp:81-91`): `url_length` is always `unsigned char` (max 255); the stack buffer is exactly 256 bytes; `url[255] = '\0'` is the last valid index. Safe.

**Group 2 — heap allocations matching read sizes** (`Ap4Descriptor.cpp:65-66`, `Ap4DecoderSpecificInfoDescriptor.cpp:63-64`): `SetDataSize(payload_size)` then `Read(..., payload_size)` — allocation size equals read size; no overflow. Max `payload_size` from the 4-byte varint encoding is 0x0FFFFFFF, not causing arithmetic overflow.

**Group 3 — SubStream size underflow** (`Ap4ObjectDescriptor.cpp:95-96`, `Ap4EsDescriptor.cpp:102-103`, `Ap4DecoderConfigDescriptor.cpp:92`): When `payload_size < bytes_consumed`, the subtraction wraps around (unsigned underflow) producing a huge `AP4_LargeSize`. However `AP4_SubStream::ReadPartial` clamps reads by both `m_Size` and the underlying container stream's bounded data, so actual reads stay within the file; no memory corruption results.

**Group 4 — `AP4_DecoderSpecificInfoDescriptor::Inspect()` multiplication** (line 94): `m_Info.GetDataSize()*3+1` — max 0x0FFFFFFF × 3 = 0x2FFFFFFD which fits in 32-bit. No overflow.

**Group 5 — IPMP allocations** (`Ap4Ipmp.cpp:138-141`, `Ap4Ipmp.cpp:143-148`, `Ap4Ipmp.cpp:151-154`): All heap allocations are sized to `payload_size - fields_size` or equivalent; no overflow.

No externally-triggerable memory safety vulnerability was confirmed across all analyzed code paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
