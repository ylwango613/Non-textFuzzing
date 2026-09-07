Now I have enough context. Let me analyze the two distinct issues I've identified across the `Create()` function.

**Group 1 analysis (lines 68-95, `Create()`):**

- `payload_size = size - AP4_ATOM_HEADER_SIZE` (unsigned subtraction — no underflow guard before line 80 check)
- `payload[0]` is accessed at line 75 unconditionally
- The `payload_size < 6` guard is at line 80 — AFTER the access to `payload[0]` at line 75
- For `size == 8` → `payload_size == 0` → `new AP4_Byte[0]` is allocated; `payload[0]` reads one byte past the zero-byte buffer (OOB read, CWE-125)

**Group 2 analysis (line 88):**

- After the seq-param loop, the invariant is `cursor <= payload_size`
- `payload[cursor++]` at line 88 reads `num_pic_params` — the bounds check `if (cursor > payload_size) return NULL` comes AFTER the access
- When `cursor == payload_size` exactly (e.g. `payload_size == 6`, `num_seq_params == 0`), `payload[payload_size]` is read one byte past the `payload_size`-byte allocation — OOB read, then the post-access check returns NULL

Both paths are externally reachable by mp42aac parsing a crafted MP4 file with a malformed `avcC` atom.

## VULN: OOB Heap Read in AP4_AvccAtom::Create() Before Size Guard (payload[0] on zero-byte buffer)
- **漏洞类别**: memory-safety
- **函数**: AP4_AvccAtom::Create()
- **行号**: 68-80
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File / AP4_AtomFactory::CreateAtomFromStream() → AP4_AtomFactory case AP4_ATOM_TYPE_AVCC (Ap4AtomFactory.cpp:479) → AP4_AvccAtom::Create(size_32=8, stream)
- **描述**: 在 `Create()` 中，`payload_size = size - AP4_ATOM_HEADER_SIZE` 对 `size==8` 时产生 0（合法值）。随后 `AP4_DataBuffer payload_data(0)` 调用 `new AP4_Byte[0]`（C++ 标准允许，返回非空指针，但分配了零字节）。在第 75 行 `if (payload[0] != 1)` 直接读取 `payload[0]`，此时 `payload` 指向一个 0 字节缓冲区，`payload[0]` 越界读一字节。有效的大小下界检查 `if (payload_size < 6) return NULL` 位于第 80 行，比越界访问晚了五行，无法防止此读取。
- **触发条件**: 在 MP4 文件中构造一个 `avcC` box，其 size 字段设为 0x00000008（仅含 8 字节头部，无 payload）。mp42aac 解析该 box 时调用 `Create(8, stream)`，即可触发对 0 字节堆缓冲区的越界读。
- **安全影响**: 堆越界读 1 字节，读取紧随其后的堆内存内容（可能属于相邻分配块）。可用于信息泄露（辅助 ASLR 绕过）或触发进程崩溃（DoS）。

## VULN: OOB Heap Read in AP4_AvccAtom::Create() — num_pic_params Access Before Bounds Check
- **漏洞类别**: memory-safety
- **函数**: AP4_AvccAtom::Create()
- **行号**: 88-89
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File / AP4_AtomFactory::CreateAtomFromStream() → AP4_AtomFactory case AP4_ATOM_TYPE_AVCC (Ap4AtomFactory.cpp:479) → AP4_AvccAtom::Create(size_32=14, stream)
- **描述**: 在 `Create()` 中，seq-param 循环结束后唯一保证的不变式是 `cursor <= payload_size`。第 88 行 `unsigned int num_pic_params = payload[cursor++]` 先读 `payload[cursor]` 再递增，而边界检查 `if (cursor > payload_size) return NULL` 在第 89 行——读取已发生后才执行。当 `cursor == payload_size` 时（例如：size=14 → payload_size=6，num_seq_params=0 → 循环不执行 → cursor=6=payload_size），`payload[6]` 读取了分配了 6 字节的缓冲区的末尾之后的 1 字节，构成堆越界读。
- **触发条件**: 构造 MP4 文件中的 `avcC` box，size=14（0x0000000E），payload 共 6 字节：payload[0]=0x01（版本）、payload[1-4] 任意、payload[5]=0xE0（num_seq_params&31==0，无序列参数）。`Create(14, stream)` 调用后，seq-param 循环零次迭代，cursor=6=payload_size，读 payload[6] 越界。
- **安全影响**: 堆越界读 1 字节，泄露紧邻该缓冲区之后的堆内容（可能是其他 box 解析数据或 allocator 元数据），可用于信息泄露（ASLR 辅助绕过）或程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
