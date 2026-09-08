I have all the context needed. The key vulnerability is in `Ap4UuidAtom.cpp` lines 160-166, confirmed through the full call chain. Here is the final report:

## VULN: Integer Underflow → Uncontrolled Heap Allocation in AP4_UnknownUuidAtom Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_UnknownUuidAtom::AP4_UnknownUuidAtom(AP4_UI64, const AP4_UI08*, AP4_ByteStream&)
- **行号**: 160-166
- **CWE**: CWE-191 (Integer Underflow → Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File` → `AP4_AtomFactory::CreateAtomFromStream` (Ap4AtomFactory.cpp:221) → UUID case (Ap4AtomFactory.cpp:509-522): reads 16-byte UUID then calls `new AP4_UnknownUuidAtom(size_64, uuid, stream)` (line 519) → `AP4_UnknownUuidAtom::AP4_UnknownUuidAtom` (Ap4UuidAtom.cpp:163): `m_Data.SetDataSize((AP4_Size)size - GetHeaderSize())` → `AP4_DataBuffer::ReallocateBuffer` → `new AP4_Byte[~4GB]`
- **描述**: `size` 为从 MP4 文件读入的 `AP4_UI64`，被强制转换为 `AP4_Size`（即 `AP4_UI32`），再减去 `GetHeaderSize()`（非大尺寸普通 UUID atom 返回 24）。工厂层的唯一下界检查为 `size < 8`（Ap4AtomFactory.cpp:215），因此 size=8…23 的 UUID atom 均可通过检查。当 `(AP4_UI32)size - 24` 发生无符号下溢时，结果约为 0xFFFFFFF8–0xFFFFFFFF（~4 GB），紧接着 `SetDataSize` → `ReallocateBuffer` → `new AP4_Byte[~4GB]` 触发巨型堆分配。
- **触发条件**: 构造一个 MP4 文件，其中包含一个 `uuid` box，size 字段设为 8 到 23 之间的任意值（如 `00 00 00 08 75 75 69 64 <...any UUID bytes...>`）。该值满足工厂 `size >= 8` 检查，但小于 UUID atom 合法最小头部尺寸 24，在构造函数中触发无符号整数下溢。
- **安全影响**: 未捕获的 `std::bad_alloc` 导致进程崩溃（DoS）；在 Linux 内存过量提交（overcommit）场景下，若分配虚拟成功，后续 `stream.Read` 写入 ~4 GB 的虚拟地址空间可引发 SIGSEGV，亦为 DoS；在异常 new 处理器环境中存在堆破坏（潜在 RCE）的理论风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
