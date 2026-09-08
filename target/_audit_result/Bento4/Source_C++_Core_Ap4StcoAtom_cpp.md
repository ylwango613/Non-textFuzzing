I have all the information needed. The full analysis is complete.

**Key finding:** In the parsing constructor (`Ap4StcoAtom.cpp:78-82`), the expression `size - AP4_FULL_ATOM_HEADER_SIZE - 4` uses unsigned 32-bit arithmetic (`AP4_UI32`). When `size` is between 12 and 15 (which passes the `size < AP4_FULL_ATOM_HEADER_SIZE` guard in `Create()` at line 49 since `AP4_FULL_ATOM_HEADER_SIZE = 12`), the subtraction `size - 12 - 4` underflows. For `size = 12`: `12 - 12 - 4 = 0xFFFFFFFC` unsigned, making the effective cap `0xFFFFFFFC / 4 = 0x3FFFFFFF`. An attacker-controlled `m_EntryCount ≤ 0x3FFFFFFF` is not clamped, and the subsequent `new AP4_UI32[0x3FFFFFFF]` and `new unsigned char[0x3FFFFFFF * 4]` attempt ~4 GB allocations → `std::bad_alloc` crash.

Attack path: crafted MP4 → `Ap4AtomFactory::CreateAtomFromStream` (factory validates `size >= 8`, size=12 passes) → `AP4_StcoAtom::Create(12, stream)` → private constructor with `size=12` → underflow → enormous allocation.

## VULN: Integer Underflow in stco Bounds Check Enables Heap Exhaustion DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-82
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size_32=12, stream) → AP4_StcoAtom 私有构造函数, 行 78
- **描述**: `size`、`AP4_FULL_ATOM_HEADER_SIZE`（值为12）和 `4` 均为 `AP4_UI32`（无符号 32 位）。当 `size = 12` 时，表达式 `size - AP4_FULL_ATOM_HEADER_SIZE - 4` = `12 - 12 - 4` = `0xFFFFFFFC`（无符号下溢），除以 4 得有效上限 `0x3FFFFFFF`。`Create()` 中只检查 `size < AP4_FULL_ATOM_HEADER_SIZE`（即 < 12），size=12 可通过。构造函数中的边界截断实际上将允许 `m_EntryCount` 达到 `0x3FFFFFFF`，随后执行 `new AP4_UI32[0x3FFFFFFF]`（约4GB）和 `new unsigned char[0x3FFFFFFF * 4]`（同约4GB），触发 `std::bad_alloc` 未捕获异常，导致进程崩溃。
- **触发条件**: 构造包含一个 `stco` box 的 MP4 文件：box 头 `size` 字段设为 12（即 `0x0000000C`），紧随 version/flags 字段之后的 4 字节（`entry_count` 字段位置）设为 `0x3FFFFFFF`。由于工厂只要求 `size >= 8`，size=12 可以正常通过解析进入 `AP4_StcoAtom::Create`。
- **安全影响**: 进程因 `std::bad_alloc` 未被捕获而崩溃，造成拒绝服务（DoS）。在服务端批量处理用户上传 MP4 的场景中可远程触发；在命令行工具场景中只需诱使用户处理一个精心构造的文件。

<!-- AUDIT_PROMPT_VERSION: 1 -->
