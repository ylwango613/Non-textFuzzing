I've completed my multi-file analysis. Group-by-group scan findings:

**Ap4SampleSource.cpp**: Thin delegation layer; no direct allocation or bounds issues in the source file itself.

**Ap4Sample.cpp (line 144)**: `size+offset` overflow in `ReadData(3-arg)` bypasses the bounds check, but that overload is unreachable from the mp42aac `WriteSamples` path.

**Ap4CttsAtom.cpp (lines 79-97)**: ❗ No bounds check on `entry_count` against atom size. `entry_count*8` is 32-bit arithmetic — overflows to 0 when `entry_count ≥ 0x20000000`. This gives a 0-byte `buffer` allocation; the loop then reads/writes OOB.

**Ap4Stz2Atom.cpp (lines 88-121)**: ❗ `(sample_count * m_FieldSize + 7) / 8` is also 32-bit arithmetic. Overflows to 0 when e.g. `m_FieldSize=16` and `sample_count=0x10000000`, resulting in `table_size=0`; the guard `(table_size+8) > size` wrongly passes; buffer = 0 bytes; loop reads OOB from it.

**Ap4SttsAtom.cpp (line 79-88)**: `entry_count` is read from file with no size check; `while (entry_count--)` loops up to 4 billion times → CPU-exhaustion DoS. Not a memory-corruption bug.

**Ap4DataBuffer.cpp (line 192)**: `existing_size+data_size` overflow in `AppendData`, but reaching it with large values from file requires a prior 2 GB+ `m_DataSize`, which is infeasible in the mp42aac path.

**Ap4Array.h EnsureCapacity**: `::operator new` throws `std::bad_alloc` rather than returning NULL, making the NULL guard dead code. Large allocation attempts from ctts/stz2 therefore propagate as unhandled exceptions → crash → DoS (64-bit). On 32-bit the size multiplication overflows first, giving a 0-byte allocation → heap OOB write.

## VULN: AP4_CttsAtom Missing Size Check + Integer Overflow → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 79-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-122 (Heap-Based Buffer Overflow) / CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(*input) → atom factory parses stbl → AP4_CttsAtom::Create() → AP4_CttsAtom::AP4_CttsAtom() → m_Entries.SetItemCount(entry_count) [OOB on 32-bit] + new unsigned char[entry_count*8=0] + loop m_Entries[i] / buffer[i*8] OOB
- **描述**: `entry_count` is read directly from the ctts box payload (line 78) with no check against the atom's declared `size`. Unlike stco/stsz/stsc (which all clamp their counts with `(size-HEADER)/ENTRY_SIZE` guards), ctts has no such guard. When `entry_count >= 0x20000000`, the expression `entry_count * 8` (both operands are 32-bit) wraps to 0 in unsigned 32-bit arithmetic. `new unsigned char[0]` allocates a valid but zero-byte buffer. `stream.Read(buffer, 0)` succeeds immediately. The loop (lines 88-97) then iterates `entry_count` times, performing `AP4_BytesToUInt32BE(&buffer[i*8])` (heap OOB read from the 0-byte buffer) and writing results into `m_Entries[i]` (heap OOB write if the m_Entries backing store also suffered a 32-bit size overflow in `EnsureCapacity`). On 64-bit systems, `EnsureCapacity` attempts a ≥4 GB allocation and throws `std::bad_alloc` (unhandled → crash); on 32-bit systems the backing store allocation also wraps to 0 bytes, making every write to `m_Entries[i]` an OOB write into arbitrary heap memory.
- **触发条件**: 构造一个 MP4 文件，其中 ctts box 的 `entry_count` 字段设为 `0x20000000`（或任何 ≥ `0x20000000` 的值），box 的实际 `size` 字段设为合法的最小值（如 12）。无需填写有效的 ctts 条目数据。
- **安全影响**: 32 位系统：堆缓冲区越界写（写入 `m_Entries` 零字节分配之外的堆内存），可被利用实现任意代码执行（RCE）。64 位系统：`std::bad_alloc` 未处理异常导致程序崩溃，可稳定触发拒绝服务（DoS）。

## VULN: AP4_Stz2Atom Integer Overflow in table_size Bypasses Guard → Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-121 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(*input) → atom factory → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom() → line 90: table_size=(sample_count*m_FieldSize+7)/8 整数溢出为0 → line 91: 守卫误通过 → line 92: new unsigned char[0] → loop lines 100-119: buffer[i/2]/buffer[i]/buffer[i*2] OOB read
- **描述**: `sample_count` 和 `m_FieldSize` 均来自 stz2 box 的文件字段（line 82/81）。在 line 90，`sample_count * m_FieldSize` 是 `AP4_Cardinal`（32-bit unsigned）与 `AP4_UI08`（提升为 int）的 32 位乘法，当乘积 ≥ 2³² 时溢出归零（例如 `m_FieldSize=16`，`sample_count=0x10000000` → `0x10000000×16=0x100000000→0`）。`table_size` 因此为 0，line 91 的守卫 `(0+8) > size` 在任何合法 size（≥12）下均为假，守卫被跳过。line 92 分配 0 字节缓冲，line 93 读取 0 字节成功。随后的 case 16 循环（line 116）对 i=0…sample_count-1 访问 `buffer[i*2]`，立即产生堆越界读；读回的堆内存内容被写入 `m_Entries[i]`，进一步污染样本大小表，可导致后续解析逻辑异常。当 i 足够大时，`buffer+i*2` 指向未映射内存，触发 SIGSEGV，程序崩溃。
- **触发条件**: 构造 MP4 文件中含有 stz2 box，`field_size=16`，`sample_count=0x10000000`（268M），box 声明的 `size` 字段为任意合法值（≥12 即可）。需要系统有约 1 GB 可用内存用于 `m_Entries` 分配；若可用内存不足则在 `SetItemCount` 处因 `std::bad_alloc` 崩溃，同样触发 DoS。
- **安全影响**: 堆越界读：读取 `buffer` 零字节分配之外的堆内存内容（潜在信息泄露）；将这些内存内容以 AP4_UI32 形式写入 `m_Entries`，污染样本大小表，可能引发后续解析中的二次内存安全问题；当越界地址进入未映射区域时，触发 SIGSEGV，导致可稳定重现的拒绝服务（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
