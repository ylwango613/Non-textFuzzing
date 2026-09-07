I now have all the information needed. Let me compile the final analysis.

**Analysis Summary:**

In `Ap4HvccAtom.cpp` private constructor `AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)` (lines 248-308):

1. `payload_size = size - AP4_ATOM_HEADER_SIZE` (line 252). The factory guarantees `size >= 8` (via check at `Ap4AtomFactory.cpp:215`), so no underflow.

2. Guard at line 255: `if (payload_size < 22) return;` — allows `payload_size == 22` through.

3. When `payload_size == 22` (box total `size == 30`): lines 259–280 safely read `payload[0]..payload[21]`. Then **line 282**: `AP4_UI08 num_seq = payload[22]` — reads the 23rd byte from a 22-byte allocation. This is a 1-byte heap OOB read.

4. In `Create()` (line 85), `AP4_DataBuffer payload_data(payload_size)` allocates exactly `payload_size = 22` bytes via `new AP4_Byte[22]`, and `stream.Read()` fills those 22 bytes. The pointer passed to the private constructor points to exactly 22 bytes — making `payload[22]` a confirmed 1-byte past-the-end heap read.

5. The OOB byte becomes `num_seq`, which drives `m_Sequences.SetItemCount(num_seq)` (allocating up to 255 `Sequence` objects). The loop immediately breaks since `cursor (23) > payload_size (22)`, so no further damage. Security impact is heap info leak (1 heap byte) that can influence subsequent allocation counts.

**Call chain**: `mp42aac input.mp4` → `AP4_File::AP4_File()` → `AP4_AtomFactory::CreateAtomFromStream()` → `AP4_HvccAtom::Create(size_32=30, stream)` → `new AP4_HvccAtom(30, 22-byte-buf)` → `payload[22]` OOB read.

## VULN: Off-by-One Heap OOB Read in AP4_HvccAtom Payload Parser
- **漏洞类别**: memory-safety
- **函数**: AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)
- **行号**: 252-282
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:484] → AP4_HvccAtom::Create(size_32=30, stream) [Ap4HvccAtom.cpp:82] → new AP4_HvccAtom(30, payload_data.GetData()) [Ap4HvccAtom.cpp:90] → AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload) [Ap4HvccAtom.cpp:248]
- **描述**: 在私有构造函数中，`payload_size = size - AP4_ATOM_HEADER_SIZE`（第252行）。当攻击者将 hvcC box 的 size 字段设置为 30（= 8 字节头 + 22 字节 payload）时，`payload_size == 22`，第255行的卫语句 `if (payload_size < 22) return;` 不会触发（22 < 22 为假）。随后第282行 `AP4_UI08 num_seq = payload[22]` 读取第23个字节，但 `Create()` 在第87行仅分配并读取了22字节（`AP4_DataBuffer payload_data(22)`，`stream.Read(m_Buffer, 22)`），造成堆上1字节越界读取。
- **触发条件**: 构造一个包含 hvcC（或 hvce）box 的 MP4 文件，将该 box 的 size 字段设为 30（0x0000001E），使得 payload 恰好为22字节；工厂的 `size >= 8` 检查通过但无上界截断，payload_size == 22 绕过卫语句。
- **安全影响**: 堆上1字节越界读取：读到的值（heap allocator元数据或相邻对象数据）驱动 `m_Sequences.SetItemCount(num_seq)` 分配最多255个 Sequence 对象，可泄露堆布局信息；在特定堆风水条件下攻击者若能控制相邻堆块内容则可操纵 `num_seq` 值影响后续解析流程（低置信度信息泄露 / DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
