I have confirmed both integer overflow arithmetic scenarios. Now I can produce the final audit report.

## VULN: AP4_MkidAtom constructor entry_count integer overflow leading to heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_MkidAtom::AP4_MkidAtom()
- **行号**: 1119-1123 (Ap4Marlin.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream → case AP4_ATOM_TYPE_MKID (context == AP4_ATOM_TYPE_MARL) → AP4_MkidAtom::Create(size_32, stream) → AP4_MkidAtom::AP4_MkidAtom(size, version, flags, stream)
- **描述**: 在 AP4_MkidAtom 的流解析构造函数（Ap4Marlin.cpp:1122）中，边界检查 `if (available < entry_count*(16+4)) return;` 对 `AP4_UI32 entry_count` 与字面量 `20` 的乘积在 32 位无符号算术下发生整数溢出。当攻击者将 MP4 文件中 mkid box 的 `entry_count` 字段设为 0xCCCCCCCD（3,435,973,837）时，`entry_count * 20` 的 32 位结果为 4，而 `available`（box 数据长度）在稍大于 4 时即可绕过该检查。随后 `m_Entries.SetItemCount(entry_count)` 被调用，在 `AP4_Array::EnsureCapacity` 内以 `count * sizeof(Entry)` 分配内存：在 32 位构建中 `sizeof(Entry)=24`，乘积再次 32 位溢出（3,435,973,837 × 24 ≈ 858,993,464 字节，远小于实际所需），导致底层分配严重不足；随后 `SetItemCount` 的初始化循环（Ap4Array.h:214）在该缓冲区之外执行数十亿次 placement-new，造成堆缓冲区溢出。在 64 位构建中，乘法不溢出（结果约 82 GB），`::operator new` 抛出 `std::bad_alloc` 导致进程崩溃（DoS）。
- **触发条件**: 攻击者构造一个顶层含 `marl` 容器的 MP4 文件，`marl` 内嵌 `mkid` box，其 `entry_count` 字段设为 0xCCCCCCCD；box 总长度设为 24 字节（使 available=8，满足绕过条件 8 ≥ 4）。mp42aac 在解析文件 box 树时（`new AP4_File(*input)`）自动触发该路径，无需任何额外命令行选项。
- **安全影响**: 在 32 位部署中，`EnsureCapacity` 因 size_t 溢出分配极小缓冲区，随后数亿次堆写操作覆盖堆元数据及相邻对象，可被利用实现任意代码执行（RCE）。在 64 位部署中，`std::bad_alloc` 异常未被捕获，导致进程崩溃（可靠 DoS）。

## VULN: AP4_MkidAtom entry_size integer overflow bypassing bounds check leading to massive heap allocation and crash
- **漏洞类别**: memory-safety
- **函数**: AP4_MkidAtom::AP4_MkidAtom()
- **行号**: 1124-1133 (Ap4Marlin.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-400 (Uncontrolled Resource Consumption)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream → case AP4_ATOM_TYPE_MKID (context == AP4_ATOM_TYPE_MARL) → AP4_MkidAtom::Create(size_32, stream) → AP4_MkidAtom::AP4_MkidAtom(size, version, flags, stream) → parsing loop at line 1124
- **描述**: 在 AP4_MkidAtom 构造函数解析每个条目的循环体内（Ap4Marlin.cpp:1127），当从文件中读取的 `entry_size`（AP4_UI32）接近 UINT32_MAX 时，边界检查 `if (available < 4+entry_size) break;` 的右操作数 `4+entry_size` 发生 32 位无符号整数上溢：例如 `entry_size=0xFFFFFFFF` 时 `4+0xFFFFFFFF=3`，`entry_size=0xFFFFFFFC` 时结果为 0。对于任何 `available≥3` 的 box（即 box 数据长度≥3 字节，几乎任何合法 box 都满足），该检查失效，循环继续执行。随后 `unsigned int content_id_size = entry_size-16`（行 1131）计算得到约 0xFFFFFFEF（≈4.29×10⁹），`new char[content_id_size]`（行 1132）尝试分配约 4 GB 内存，`::operator new` 因 OOM 抛出 `std::bad_alloc`，导致进程崩溃。
- **触发条件**: 攻击者构造 mkid box，将某个条目的 `entry_size` 字段设为 0xFFFFFFFF（或 0xFFFFFFFC～0xFFFFFFFF 范围内任意值），同时确保 box 的 `available` 字节数≥3（只需 box 总大小≥19 字节）。entry_count≥1 即可触发第一次循环迭代。
- **安全影响**: `std::bad_alloc` 异常未被 mp42aac 或库层捕获，导致进程立即崩溃（可靠 DoS）。若平台或自定义 new_handler 使 `new` 返回 NULL 而非抛出异常，随后 `stream.Read(NULL, 0xFFFFFFEF)` 将引发 NULL 指针解引用崩溃；若在极端条件下（32 位系统 size_t 再次溢出导致微小分配成功），`stream.Read` 将把约 4 GB 文件数据写入数字节的缓冲区，构成堆缓冲区溢出。

<!-- AUDIT_PROMPT_VERSION: 1 -->
