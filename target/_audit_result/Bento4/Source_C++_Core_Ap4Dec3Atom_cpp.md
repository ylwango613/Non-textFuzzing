Now I have complete context. Let me trace through the critical code path precisely:

**Key finding in `AP4_Dec3Atom::AP4_Dec3Atom` (lines 79–105):**
- Line 80 checks `if (payload_size < 3)` — so the loop body executes when `payload_size >= 3`
- Line 97 reads `payload[3]` when `num_dep_sub != 0` — but only 3 bytes (`payload[0..2]`) are guaranteed by the check
- When `payload_size == 3`, `payload[3]` is a 1-byte heap OOB read
- Line 99: `payload_size -= 4` when `payload_size == 3` → unsigned underflow to `0xFFFFFFFF`
- With `substream_count` up to 8 (bits 2:0 of payload[1]), subsequent iterations bypass the bounds check entirely, extending OOB reads across ~28 more bytes of adjacent heap

**Trigger path:** `size_32 = 13` in the dec3 box (factory check at line 215 of AtomFactory only guards `size < 8`, so 13 passes), then with bits 4:1 of the 3rd payload byte nonzero (`num_dep_sub != 0`). `substream_count` derived from `payload[1] & 7` can be set to 7 (max), amplifying the OOB further.

The factory check at AtomFactory.cpp:215 (`size > 0 && size < 8`) does prevent the underflow in `Create` itself, but does **not** prevent the OOB in the parsing loop.

## VULN: Heap OOB Read in AP4_Dec3Atom Substream Parsing via payload[3] Access
- **漏洞类别**: memory-safety
- **函数**: AP4_Dec3Atom::AP4_Dec3Atom()
- **行号**: 96-104
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File parsing → AP4_AtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:717] → AP4_Dec3Atom::Create(size_32=13, stream) [Ap4Dec3Atom.cpp:46] → AP4_Dec3Atom::AP4_Dec3Atom(size=13, payload) [Ap4Dec3Atom.cpp:62] → loop iteration at substream i=0 with num_dep_sub≠0 → payload[3] OOB read [Ap4Dec3Atom.cpp:97]
- **描述**: 在 `AP4_Dec3Atom` 构造函数的子流解析循环中，代码在第 80 行仅检查 `payload_size < 3`（保证 3 字节可用），但在第 97 行当 `num_dep_sub != 0` 时访问 `payload[3]`（需要 4 字节）。当 `payload_size == 3` 时，`payload[3]` 越过堆分配缓冲区末尾 1 字节进行非法读取。随后第 99 行 `payload_size -= 4`（无符号整数，3-4）下溢为 `0xFFFFFFFF`，致使后续最多 7 次子流迭代（substream_count 最大值为 8）全部绕过边界检查，在堆上连续向后读取数十字节的堆内存（相邻堆分配元数据或其他对象内容）。
- **触发条件**: 构造一个包含 `dec3` box 的 MP4 文件，其中：(1) `dec3` box 的 size 字段设置为 13（payload 共 5 字节，解析头部 2 字节后剩余 3 字节），满足工厂检查 `size >= 8`；(2) payload 第 2 字节（index 2）的 bits[4:1] 设为非零值使 `num_dep_sub != 0`；(3) 可选：将 payload[1] 的低 3 位设为 7（substream_count=8）以最大化 OOB 范围，此时 payload_size 下溢放大后续读取。
- **安全影响**: 堆越界读取可泄露相邻堆内存内容（堆元数据、指针、其他解析对象），在 ASLR 环境下可用于信息泄露以绕过地址随机化；若越界区域包含函数指针或对象 vptr，可辅助构造后续 RCE 攻击。最坏情况为信息泄露（Info Leak）+ 辅助 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
