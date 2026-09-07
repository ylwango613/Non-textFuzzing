After thoroughly analyzing `Ap4OddaAtom.cpp` and all relevant context:

**Group 1 (lines 58–76): parsing constructor**
- `stream.ReadUI64(m_EncryptedDataLength)` — attacker-controlled UI64
- `new AP4_SubStream(stream, position, m_EncryptedDataLength)` — SubStream constructor stores the size as metadata only; no allocation of `m_EncryptedDataLength` bytes
- `stream.Seek(position + m_EncryptedDataLength)` — potential wrap-around if sum exceeds UINT64_MAX, but this only mispositions the parser; it is not a memory-safety issue

**Group 2 (lines 143–161): WriteFields**
- `m_EncryptedPayload->CopyTo(stream, m_EncryptedDataLength)` — `CopyTo` uses a fixed stack buffer (`AP4_BYTE_STREAM_COPY_BUFFER_SIZE`), loops chunk-by-chunk, returns error on EOS; no allocation proportional to `m_EncryptedDataLength`

**Group 3 (line 169): InspectFields**
- `(AP4_UI32)m_EncryptedDataLength` — UI64→UI32 truncation only affects display text; no memory operation depends on the truncated value

**SubStream ReadPartial arithmetic (Ap4ByteStream.cpp:446)**
- `m_Position + bytes_to_read > m_Size`: both operands promote to uint64; in pathological cases (m_Position near UINT64_MAX) the addition wraps, defeating the clamp — but m_Position can never grow past the physical EOF of the underlying file stream, so this edge case is unreachable with any real file

**Decryption path (Ap4OmaDcf.cpp:301)**
- `new AP4_SubStream(encrypted_stream, 16, encrypted_size-16)` — only metadata stored; no heap allocation of that size
- `AP4_DecryptingStream::Create` — stores size metadata; no buffer allocation proportional to cleartext/encrypted size

No code path allocates memory whose size comes from `m_EncryptedDataLength` or any other attacker-controlled field in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
