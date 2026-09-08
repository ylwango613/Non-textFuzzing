I now have all the context needed. Let me do a complete analysis pass.

**Bounds check analysis (lines 76–82):**
- `AP4_ATOM_HEADER_SIZE = 8`, `AP4_FULL_ATOM_HEADER_SIZE = 12`
- After `ReadFullHeader` consumes 4 bytes (version+flags) and `ReadUI32(entry_count)` consumes 4 more, the stream position is at byte 16
- Actual remaining data: `size - 16` bytes
- Bounds check uses `(size - 12) / 12`, which is off by 4 (should be `(size - 16) / 12`)
- This allows reading 4 bytes past the declared box boundary from stream — a correctness bug, but NOT a heap buffer overflow since `buffer` is correctly sized at `entry_count*12`

**Integer overflow analysis — `EnsureCapacity` (lines 81, via `SetItemCount`):**
- `m_Entries.SetItemCount(entry_count)` → `EnsureCapacity(entry_count)` → `::operator new(count * sizeof(T))`
- `count = entry_count` (AP4_UI32, 32-bit), `sizeof(AP4_StscTableEntry) = 20` (5 × uint32)
- **On 32-bit** (`size_t` = 32-bit): `entry_count * 20` overflows when `entry_count > 214,748,364`
  - Bounds check permits up to `(size-12)/12 ≈ 357,913,940` — far above the overflow threshold
  - Example: `entry_count=214,748,365` → `214748365 * 20 = 4294967300 mod 2^32 = 4` → allocates **4 bytes**
  - Loop then placement-new's 214,748,365 × 20-byte objects into 4 bytes → **massive heap overflow**
  - Required declared box size: `12 + 12 × 214748365 = 2,576,980,392` (valid uint32, file can be tiny)
- **On 64-bit**: `AP4_UI32 * size_t` promotes to 64-bit, no overflow; allocation would be ~6.7 GB → throws `bad_alloc` (DoS only)

**`new unsigned char[entry_count*12]` (line 82):**
- `entry_count * 12` computed as `AP4_UI32 * int → unsigned int` (32-bit)
- Max bounded value: `357913940 * 12 = 4294967280 < 2^32` → no overflow on either 32-bit or 64-bit

**Caller's chunk-offset use (verified):**
- `GetChunkOffset` in stco has an explicit bounds check (`chunk > m_EntryCount || chunk == 0`) before the array access — no OOB exploitable from downstream

**Accumulation overflow in `first_sample` (lines 94–95):**
- `m_ChunkCount = first_chunk - prev.m_FirstChunk` can wrap (unsigned); propagates to `first_sample`
- Results in incorrect `m_FirstSample` values stored in entries — a logic/semantic bug, no direct memory safety impact within this file

## VULN: Integer overflow in EnsureCapacity → heap buffer overflow on 32-bit builds
- **漏洞类别**: memory-safety
- **函数**: AP4_StscAtom::AP4_StscAtom() → AP4_Array<AP4_StscTableEntry>::SetItemCount() → EnsureCapacity()
- **行号**: 81-82 (触发点 SetItemCount), Ap4Array.h:172 (整数溢出发生在 EnsureCapacity 内)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_StscAtom::Create() → new AP4_StscAtom(size, version, flags, stream) → m_Entries.SetItemCount(entry_count) → AP4_Array::EnsureCapacity(entry_count) → ::operator new(entry_count * sizeof(AP4_StscTableEntry)) [integer overflow on 32-bit]
- **描述**: 在 32-bit 编译版本中，`SetItemCount(entry_count)` 调用 `EnsureCapacity(entry_count)`，后者执行 `::operator new(count * sizeof(AP4_StscTableEntry))`。`count`（AP4_UI32）与 `sizeof(AP4_StscTableEntry) = 20`（size_t，32-bit 上为 32-bit）相乘时，当 `entry_count > 214,748,364` 时结果溢出 32-bit size_t。例如 `entry_count = 214,748,365` 时乘积 `4,294,967,300 mod 2^32 = 4`，仅分配 4 字节；随后 placement-new 循环将 `entry_count`（共 2.14 亿）个 20-byte `AP4_StscTableEntry` 对象写入该 4 字节缓冲区，造成巨型堆溢出。bounds check（行 78-80）使用 `(size-12)/12`，允许 `entry_count` 最大达 357,913,940，远超溢出阈值。
- **触发条件**: 构造一个 stsc box，在文件中声明 `size = 2,576,980,392`（通过 bounds check），`entry_count = 214,748,365`（触发 32-bit size_t 溢出）；文件实际内容可极小（stream.Read 失败前 SetItemCount 已执行溢出），适用于 32-bit 编译的 mp42aac。
- **安全影响**: 堆内存大规模越界写入（写入零值），破坏后续堆块元数据，在 32-bit 平台上可能被利用实现远程代码执行（RCE）；至少导致程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
