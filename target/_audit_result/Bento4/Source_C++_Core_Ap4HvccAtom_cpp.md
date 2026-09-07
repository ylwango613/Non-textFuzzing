I've confirmed the off-by-one issue. The guard `if (payload_size < 22) return;` allows `payload_size == 22` to proceed, but `payload[22]` is accessed at line 282 — index 22 is out of bounds for a 22-byte buffer (valid indices: 0..21). This is the only real memory safety finding in this file. All loop-body payload accesses have correct bounds guards. The `SetItemCount` unchecked-return paths only OOB if `::operator new` returns NULL rather than throwing, which is not exploitable via file content on standard platforms.

## VULN: Off-by-One Heap OOB Read in hvcC Atom Parsing Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_HvccAtom::AP4_HvccAtom(AP4_UI32, const AP4_UI08*)
- **行号**: 255-282
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_HvccAtom::Create(size_32=30, stream) → new AP4_HvccAtom(30, payload_data.GetData()) → AP4_HvccAtom::AP4_HvccAtom(AP4_UI32, const AP4_UI08*) → payload[22] OOB read
- **描述**: 解析构造函数第 255 行的边界检查为 `if (payload_size < 22) return;`，当 `payload_size == 22` 时条件为假（22 < 22 = false），执行继续。第 282 行随即读取 `payload[22]`，而 `payload` 缓冲区仅有 22 字节（有效索引 0..21），导致 1 字节堆越界读取。堆上该位置存放的是 allocator 元数据或相邻分配的数据，属于信息泄露或潜在 crash。
- **触发条件**: 构造一个 hvcC box，box 总大小字段设为 30（8 字节头 + 22 字节 payload）。atom factory 的 `size >= 8` 检查通过（30 ≥ 8），`payload_size = 30 - 8 = 22`，`payload_size < 22` 为 false，进入解析逻辑后访问 `payload[22]` 造成 1 字节堆 OOB 读。
- **安全影响**: 信息泄露——可读取紧随 payload 缓冲区之后的 1 字节堆内存（可能含指针、计数器等内部状态）；在特定堆布局下也可能导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
