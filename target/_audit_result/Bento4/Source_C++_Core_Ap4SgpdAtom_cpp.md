Complete analysis done. Summary of findings:

- **Line 80**: `AP4_Size bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE` — `AP4_Size` is `AP4_UI32` (unsigned)
- **Lines 82/85/92**: `bytes_available -= 4` three times with no pre-check that `bytes_available >= 4`
- `Create()` only enforces `size >= AP4_FULL_ATOM_HEADER_SIZE (12)`, so size=12 → bytes_available=0
- First decrement: `0 - 4 = 0xFFFFFFFC` (unsigned wrap) → subsequent decrements make it `0xFFFFFFF8`
- Line 99 (version=0): `description_length = bytes_available` = ~4 GB
- Line 105: `if (description_length <= bytes_available)` → `4294967288 <= 4294967288` → **TRUE** (bounds check completely bypassed)
- Line 108: `payload->SetDataSize(4294967288)` → `ReallocateBuffer` → `new AP4_Byte[4294967288]` → uncaught `std::bad_alloc` → crash

- **Line 102**: `description_length = stream.ReadUI32(description_length)` — `ReadUI32` returns `AP4_Result` (int), so the actual stream-read value (via reference) is immediately overwritten by the return code (0 = AP4_SUCCESS). Logic bug but only causes DoS when combined with the bytes_available underflow.

## VULN: Unsigned Integer Underflow in bytes_available Bypasses Bounds Check Leading to Uncontrolled Heap Allocation (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_SgpdAtom::AP4_SgpdAtom()
- **行号**: 80-113
- **CWE**: CWE-191 (Integer Underflow) → CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() → AP4_SgpdAtom::Create(size_32=12, stream) → AP4_SgpdAtom::AP4_SgpdAtom(size=12, version=0, ...) → bytes_available underflow → SetDataSize(~4GB) → new AP4_Byte[4294967288] → uncaught std::bad_alloc → std::terminate()
- **描述**: `bytes_available` 的类型为 `AP4_Size`（即 `AP4_UI32`，无符号 32 位整数）。在第 80 行初始化为 `size - AP4_FULL_ATOM_HEADER_SIZE`；而 `Create()` 仅检查 `size >= 12`（AP4_FULL_ATOM_HEADER_SIZE），所以当攻击者将 sgpd box 的 size 字段设为 12 时，bytes_available = 0。随后第 82 行无条件执行 `bytes_available -= 4`（version=0 时）、第 92 行再减 4，均未先检查 bytes_available 是否 ≥ 4，导致无符号整数向下溢出，bytes_available 变为 ~0xFFFFFFF8（约 4 GB）。进入 entry 循环后（version=0 分支，第 99 行），`description_length = bytes_available ≈ 4 GB`；第 105 行的边界检查 `description_length <= bytes_available` 退化为恒真，完全失效。随后第 108 行调用 `payload->SetDataSize(4294967288)`，内部执行 `new AP4_Byte[4294967288]`，抛出未被捕获的 `std::bad_alloc`，进程崩溃。
- **触发条件**: 构造一个 MP4 文件，其中包含 sgpd box：size 字段设为 12（最小合法值），version=0，然后在 box 边界之后（流中）紧跟合法字节，使 ReadUI32(grouping_type) 和 ReadUI32(entry_count) 均读取成功（entry_count ≥ 1）。整个 box 的 size 声明只有 12 字节但 entry_count > 0，即可触发。
- **安全影响**: 攻击者提供一个精心构造的 MP4 文件即可让 mp42aac 进程因未捕获的 std::bad_alloc 崩溃（DoS）。若目标平台启用 Linux 内存过提交（overcommit），4 GB 的 new[] 可能不会立即失败，此时 stream.Read 将读取流中超出 box 声明范围的字节写入堆缓冲区，造成跨 box 边界的越界流读取；但更常见的结果是进程因 std::bad_alloc 被 std::terminate() 终止（崩溃 / DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
