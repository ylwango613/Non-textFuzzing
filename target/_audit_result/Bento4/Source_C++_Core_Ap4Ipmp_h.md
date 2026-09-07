I now have a complete picture of the entire call chain and all allocation paths. Let me compile the analysis before writing the final report.

**Group 1 — Ap4Ipmp.cpp lines 118-156 (constructor from stream)**

Branch `m_DescriptorId==0xFF && m_IpmpsType==0xFFFF` (lines 129-141):
- `fields_size = 3+3 = 6`. Actual bytes consumed before data = 3(id+type) + 2(DescriptorIdEx) + 16(ToolId) + 1(ControlPointCode) = 22. `fields_size` is 16 short. The `m_Data` buffer is correctly sized to `payload_size-6` and `stream.Read()` writes exactly that many bytes. No heap overflow — just reads from wrong stream offsets (logical bug, not memory safety).

Branch `m_IpmpsType==0` (lines 142-149):
- `new char[1+payload_size-3]`. `payload_size` is `AP4_UI32` from the 4-byte MPEG-4 varint decoder (max = 0x0FFFFFFF = 268,435,455). Arithmetic: `1+0x0FFFFFFF-3 = 0x0FFFFFFD` — no 32-bit overflow, no underallocation.  
- `buffer[payload_size-3] = '\0'` lands at index `payload_size-3`, which is the last valid byte of the `payload_size-2`-element array. Correct.
- `stream.Read(buffer, payload_size-3)` reads exactly `payload_size-3` bytes into buffer[0..payload_size-4]. No overflow.
- `AP4_String::Assign(buffer, payload_size-3)`: allocates `payload_size-3+1 = payload_size-2` chars, copies `payload_size-3` bytes. Correct.

Branch `else` (lines 150-154):
- `m_Data.SetDataSize(payload_size-3)` → `ReallocateBuffer(payload_size-3)` → `new AP4_Byte[payload_size-3]`. Then `stream.Read(m_Data.UseData(), payload_size-3)`. Buffer and read size match. No overflow.

**Group 2 — Varint decoder (Ap4DescriptorFactory.cpp lines 66-78)**
Four 7-bit iterations → max `payload_size = 0x0FFFFFFF`. No integer overflow possible in the decoder itself or in any downstream allocation using `payload_size`.

**Group 3 — SubStream bounds (Ap4ByteStream.cpp)**
`AP4_SubStream::ReadPartial` clamps `bytes_to_read` to `m_Size - m_Position`, preventing any OOB read even when the SubStream size was derived from unsigned underflow in `AP4_ObjectDescriptor`.

**Group 4 — AP4_DataBuffer::AppendData (Ap4DataBuffer.cpp line 192)**
`existing_size + data_size` can overflow → mismatched SetDataSize → heap overflow. But this function is NOT called from any IPMP parsing code path in `Ap4Ipmp.cpp`.

**Group 5 — AP4_IpmpDescriptor::SetData (Ap4Ipmp.cpp line 165)**
`m_PayloadSize += data_size` can overflow unsigned 32-bit. Called only from Marlin encryption setup code, not from stream-based MP4 file parsing.

**Conclusion**: All allocations in the IPMP parsing path are correctly sized; no integer arithmetic produces an underflow that shrinks an allocation below the write size; `AP4_SubStream` enforces boundaries; the one read/allocation mismatch in `fields_size` is a logical parsing error (wrong data read from stream) but not a heap overflow. No memory safety vulnerability exists in the directly reachable `Ap4Ipmp.h` / `Ap4Ipmp.cpp` code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
