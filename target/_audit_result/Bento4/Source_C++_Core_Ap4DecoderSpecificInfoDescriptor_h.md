Based on my thorough analysis:

**Group 1 — `.h` header**: The header defines `AP4_DecoderSpecificInfoDescriptor` with two constructors, a destructor, `WriteFields`, `Inspect`, and `GetDecoderSpecificInfo`. No memory management in the header itself.

**Group 2 — Constructor (stream)** (`Ap4DecoderSpecificInfoDescriptor.cpp`, lines 58–65):
- `m_Info.SetDataSize(payload_size)` → allocates `payload_size` bytes via `new AP4_Byte[]`; if OOM it throws, it does not return failure silently (since `m_BufferIsLocal` is always true for default-constructed `AP4_DataBuffer`).
- `stream.Read(m_Info.UseData(), payload_size)` — return value unchecked; this can leave partial/uninitialized data in the buffer, but `m_DataSize` is already set to `payload_size`. Uninitialized memory risk, but not directly written to the .aac output in the mp42aac path.

**Group 3 — Parser payload_size limit** (`Ap4DescriptorFactory.cpp`, lines 66–78):
The MPEG-4 descriptor size field uses a variable-length encoding: up to 4 bytes × 7 bits = 28 bits. Maximum parseable `payload_size` = `0x0FFFFFFF` = 268,435,455.

**Group 4 — `Inspect()` integer arithmetic** (`Ap4DecoderSpecificInfoDescriptor.cpp`, lines 94–98):
`new char[m_Info.GetDataSize()*3+1]`: multiplication `AP4_UI32 * int` is computed in 32-bit `unsigned int` arithmetic. For overflow (wrap) to occur, needs `GetDataSize() ≥ 0x55555556` (~1.43B). But `payload_size` from parser ≤ `0x0FFFFFFF`, so `0x0FFFFFFF × 3 = 0x2FFFFFFD` — **no 32-bit overflow possible**. Loop bounds and `AP4_FormatString(buf, 4, ...)` writes are within allocated range.

**Group 5 — mp42aac call graph**: `Inspect()` is never called from mp42aac. The `GetDecoderSpecificInfo()` data is copied to `m_DecoderInfo` via `SetData()`, which re-allocates correctly. No UAF: the `dsi_desc` pointer is used synchronously while its owner is alive.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
