**Analysis complete.** Let me summarize the key findings from the thorough examination:

**Ap4Ipmp.cpp** (221 lines, fully read) contains two main classes: `AP4_IpmpDescriptorPointer` and `AP4_IpmpDescriptor`. The critical parsing constructor is at lines 117–155.

**`fields_size` undercounting (lines 128–140):** In the `m_DescriptorId == 0xFF && m_IpmpsType == 0xFFFF` branch, `fields_size = 3+3 = 6` but actually 22 bytes are consumed (DescriptorId:1 + IpmpsType:2 + DescriptorIdEx:2 + ToolId:16 + ControlPointCode:1). The ToolId's 16 bytes are never added to `fields_size`. This causes the code to allocate and read `payload_size – 6` bytes instead of `payload_size – 22`, reading 16 extra bytes from adjacent descriptors/atoms. However, **both the allocation (`m_Data.SetDataSize`) and the read (`stream.Read`) use the same value `payload_size – fields_size`**, so the buffer is correctly sized for what is written — no heap overflow occurs. The bug is a logical parsing error (cross-reading adjacent descriptor data), not a memory safety violation.

**`m_IpmpsType == 0` branch (lines 143–147):** `new char[1+payload_size-3]` with payload_size bounded to 28 bits by the MPEG-4 expandable encoding — no integer overflow. The index `buffer[payload_size-3]` is exactly the last valid element. No heap overflow.

**Stream bounds:** Both `AP4_SubStream::ReadPartial` and `AP4_MemoryByteStream::ReadPartial` clamp reads to available size, so over-reading the stream never produces an OOB memory access in backing buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
