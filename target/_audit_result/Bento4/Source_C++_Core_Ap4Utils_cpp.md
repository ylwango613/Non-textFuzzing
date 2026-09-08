All analysis is complete. The factory validates `size >= 8` (line 215), so `payload_size >= 0` is guaranteed, and the `< 11` guard eliminates trivially small payloads. The OOB is triggered when the v1 parsing branch exhausts the 88-bit (11-byte) buffer and attempts one more `ReadBits(8)` for the first loop iteration — `ReadCache()` then reads 4 bytes past the padded heap buffer.

## VULN: AP4_BitReader::ReadCache heap out-of-bounds read via crafted dac4 atom
- **漏洞类别**: memory-safety
- **函数**: AP4_BitReader::ReadCache()
- **行号**: 428-434
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:724] → AP4_Dac4Atom::Create(size_32, stream) [Ap4Dac4Atom.cpp:45] → AP4_Dac4Atom::AP4_Dac4Atom(size, payload) [Ap4Dac4Atom.cpp:75] → AP4_BitReader bits(payload, payload_size) [Ap4Utils.cpp:382-392] → bits.ReadBits(8) [Ap4Dac4Atom.cpp:116, loop iteration 1] → AP4_BitReader::ReadBits() calls ReadCache() with m_Position == padded_buffer_size [Ap4Utils.cpp:451] → AP4_BitReader::ReadCache() reads 4 bytes beyond heap allocation [Ap4Utils.cpp:429-434]
- **描述**: `AP4_BitReader::ReadCache()`（Ap4Utils.cpp:429）计算 `out_ptr = m_Buffer.GetData() + m_Position` 后直接访问 `out_ptr[0..3]`，完全没有检查 `m_Position` 是否超过 `m_Buffer.GetBufferSize()`。构造函数（Ap4Utils.cpp:387）将内部缓冲区向上对齐至 4 字节边界（padded_size = ceil(data_size/4)×4），并对填充字节清零，但没有任何运行时守卫阻止 `m_Position` 超过 padded_size。当 `ReadBits()` / `ReadBit()` / `SkipBits()` 在缓存耗尽时调用 `ReadCache()`，若此时 `m_Position == padded_size`，则读取堆分配块之后 4 字节的内存，构成堆越界读。
- **触发条件**: 在 MP4 文件的 `ac-4`（type=`AC_4`）sample entry 内嵌入一个 `dac4` 子 atom，使其 payload 恰好为 11 字节（满足 `payload_size >= 11` 的最小守卫）；将前 3 位设置为 `001`（ac4_dsi_version=1），接下来 7 位设置为全零（bitstream_version=0，跳过 optional program_uuid 分支），n_presentations 字段设为 ≥1。此时 v1 解析路径共消耗：3+7+1+4+9+2+32+32=90 bits，字节对齐后再跳过 6 bits，恰好耗尽全部 88 bits（padded 到 12 字节）且 m_BitsCached=0；循环首次迭代调用 `ReadBits(8)` 时，`ReadCache()` 在 `m_Position=12`（已越过 12 字节 padded buffer 末端）处读 4 字节，触发越界。
- **安全影响**: 直接后果为读取堆分配块之后 4 字节的内存，可泄露堆上其他对象（如密钥、文件路径、解密数据）的内容（信息泄露 / CWE-200）；若读取地址落在未映射页，则进程崩溃（DoS）。结合信息泄露可辅助绕过 ASLR，进一步提升利用等级。

<!-- AUDIT_PROMPT_VERSION: 1 -->
