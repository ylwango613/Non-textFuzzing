Now I have complete context. Let me analyze both the `Create()` validation loop and the constructor carefully.

**Analysis of `Create()` function (lines 65-96):**

**Finding 1 — line 75**: Version check `payload[0] != 1` runs BEFORE the size guard `if (payload_size < 6)` at line 80. When `size == AP4_ATOM_HEADER_SIZE` (8), `payload_size = 0`, `new AP4_Byte[0]` allocates a zero-byte buffer, and `payload[0]` reads one byte past it — OOB read.

The factory at Ap4AtomFactory.cpp:215 allows `size == 8`:
```cpp
if ((size > 0 && size < 8) || size > bytes_available)  // size==8 passes
```
So `payload_size = 0` is reachable.

**Finding 2 — line 88**: After the seq-params loop, the guard is:
```cpp
if (cursor > payload_size) return NULL;   // line 87: ensures cursor ≤ payload_size
unsigned int num_pic_params = payload[cursor++];   // line 88: reads BEFORE checking
if (cursor > payload_size) return NULL;   // line 89: check AFTER the read
```
When cursor == payload_size (e.g., `num_seq_params=1, param_length=0, payload_size=8` → cursor reaches 8 == payload_size), `payload[cursor]` reads one byte past the heap-allocated buffer.

## VULN: OOB Read — version check before size guard in AP4_AvccAtom::Create()
- **漏洞类别**: memory-safety
- **函数**: AP4_AvccAtom::Create()
- **行号**: 68-80
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_AvccAtom::Create(size=8, stream)
- **描述**: 在 `Create()` 中，`payload_size = size - AP4_ATOM_HEADER_SIZE`，当 MP4 文件中 `avcC` atom 的 size 字段恰好等于 8（即 `AP4_ATOM_HEADER_SIZE`）时，`payload_size = 0`。随后 `AP4_DataBuffer payload_data(0)` 调用 `new AP4_Byte[0]`，C++ 返回合法非空指针但缓冲区无有效字节。第 75 行 `payload[0] != 1` 的版本检查在第 80 行 `if (payload_size < 6) return NULL` 的尺寸保护之前执行，导致对 0 字节堆缓冲区边界外第 1 字节的越界读。
- **触发条件**: 构造一个 `avcC` atom，其 4 字节 size 字段值为 `0x00000008`（即 size=8，payload 为空），atom factory 的检查 `(size > 0 && size < 8) || size > bytes_available` 对 size=8 不拦截，会将 size_32=8 直接传入 Create()。
- **安全影响**: 越界读取堆相邻内存（可能包含其他对象数据或 heap metadata），导致信息泄露；亦可能因读取不可访问地址导致进程崩溃（DoS）。

## VULN: OOB Read — num_pic_params read without pre-check in AP4_AvccAtom::Create()
- **漏洞类别**: memory-safety
- **函数**: AP4_AvccAtom::Create()
- **行号**: 87-89
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_AvccAtom::Create(size, stream)，seq-params 循环结束后 cursor 恰好等于 payload_size
- **描述**: 在 seq-params 验证循环结束后，第 87 行 `if (cursor > payload_size) return NULL` 确保 `cursor ≤ payload_size`，但随即第 88 行 `unsigned int num_pic_params = payload[cursor++]` 在没有前置边界检查的情况下读取 `payload[cursor]`。当 `cursor == payload_size` 时（例如：`payload_size=8, num_seq_params=1, param_length=0`，循环后 cursor=8），该读取越过 `new AP4_Byte[8]` 分配的堆缓冲区末尾一个字节，属于堆越界读。第 89 行的 `if (cursor > payload_size) return NULL` 检查发生在越界读之后，无法阻止越界访问。
- **触发条件**: 构造 `avcC` atom：`size=16`（payload_size=8），`payload[0]=1`（版本），`payload[5]&31=1`（num_seq_params=1），`payload[6..7]=0x00 0x00`（param_length=0），使循环后 cursor=8=payload_size，触发 `payload[8]` 越界读。
- **安全影响**: 越界读取堆相邻内存（heap metadata 或其他对象数据），造成敏感信息泄露；在某些内存布局下读取不可访问页可致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
