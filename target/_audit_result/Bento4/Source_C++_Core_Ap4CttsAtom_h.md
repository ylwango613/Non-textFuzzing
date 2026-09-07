I now have the complete picture. Here is the complete analysis:

**Root cause (Ap4CttsAtom.cpp lines 78–97):**

- `entry_count` is `AP4_UI32 = unsigned int` (32-bit), read verbatim from the MP4 stream.
- `entry_count * 8` at line 80 is `unsigned int * int` → `unsigned int` (32-bit multiply). When `entry_count ≥ 0x20000000`, the result wraps: e.g. `0x20000001 * 8 = 8 (mod 2^32)`.
- `new unsigned char[8]` allocates 8 bytes. `stream.Read(buffer, 8)` reads 8 bytes.
- The loop at line 88 runs `entry_count` (e.g. 536,870,913) iterations, accessing `buffer[i*8]` → heap OOB read starting at `i=1`.
- On 32-bit: `EnsureCapacity` in `SetItemCount` has the same overflow (`count * sizeof(T)` as `unsigned int`), undersizing `m_Entries`; the loop also writes OOB into `m_Entries[i]` → heap write OOB.
- No upper-bound check on `entry_count` relative to the declared atom `size` field.
- Call chain: `mp42aac main()` → `AP4_File()` → `AP4_AtomFactory::CreateAtomFromStream()` (Ap4AtomFactory.cpp:457-459) → `AP4_CttsAtom::Create()` → private constructor → line 80.

## VULN: Integer Overflow in AP4_CttsAtom Constructor Leads to Heap Buffer Over-Read/Write
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-97
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122/125 (Heap-based Buffer Overflow / Out-of-bounds Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:457-459, case AP4_ATOM_TYPE_CTTS] → AP4_CttsAtom::Create(size_32, stream) → new AP4_CttsAtom(size, version, flags, stream) → Ap4CttsAtom.cpp:78: stream.ReadUI32(entry_count) → line 80: new unsigned char[entry_count*8] [integer overflow] → lines 88-97: loop reads buffer[i*8] out-of-bounds
- **描述**: `entry_count` 从 MP4 文件直接读取（`AP4_UI32 = unsigned int`，32 位）。第 80 行 `new unsigned char[entry_count*8]` 中 `entry_count*8` 为 32 位无符号乘法，当 `entry_count ≥ 0x20000000` 时发生整数回绕（例如 `0x20000001 * 8 = 8 mod 2^32`），分配仅 8 字节的堆缓冲区；而第 88-97 行的 for 循环仍执行 `entry_count` 次，`buffer[i*8]` 在 `i=1` 起即越界读取任意堆内存。在 32 位平台上，`AP4_Array::EnsureCapacity` 中 `count*sizeof(T)` 同样发生 32 位溢出，`m_Entries` 也被严重低估，循环对 `m_Entries[i]` 的写操作导致堆写越界；在 64 位平台上，写操作受大内存分配保护，但读操作仍越界。整个过程中 `entry_count` 未对照 atom 的 `size` 字段做任何上界校验。
- **触发条件**: 构造一个 ctts box，将 box 的 `size` 字段设置为合法的小值（如 24 字节），但将 `entry_count` 字段设置为 `0x20000001`（或任何 ≥ 0x20000000 且使 `entry_count*8` 发生 32 位回绕的值）。用 `mp42aac <crafted.mp4> out.aac` 运行即可触发。
- **安全影响**: 32 位：堆写越界，攻击者可通过布局堆数据实现任意代码执行（RCE）。64 位（内存过度提交场景）：堆越界读泄露堆内存内容（敏感信息泄露），并因异常访问导致进程崩溃（DoS）。最坏情况为远程代码执行（若 mp42aac 部署在自动化媒体处理服务中）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
