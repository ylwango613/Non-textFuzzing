I've gathered sufficient context. Let me now verify the key finding precisely.

**Group 1 — `AP4_NullTerminatedStringAtom` constructor (Ap4Atom.cpp:466-476)**

```
str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE;  // AP4_UI32 arithmetic
char* str = new char[str_size];                    // new char[0] when size==8
stream.Read(str, str_size);
str[str_size-1] = '\0';                            // str[0xFFFFFFFF] OOB write
```

When `size == 8` (atom has only header, no payload): `str_size = 0`, `str_size-1 = 0xFFFFFFFF` (unsigned wraparound), writing `'\0'` at `str + 0xFFFFFFFF`.

**Reachability chain**: `mp42aac` → `new AP4_File(*input)` → `ParseStream` → `AP4_DefaultAtomFactory::CreateAtomFromStream` (Ap4AtomFactory.cpp:524-525) → `new AP4_NullTerminatedStringAtom(AP4_ATOM_TYPE_8ID_, size_64=8, stream)`.

**Size guard check** (Ap4AtomFactory.cpp:215): `if ((size > 0 && size < 8) || size > bytes_available)` — `size == 8` passes this guard (not rejected). Confirmed externally triggerable by placing an `8id ` atom with 32-bit size field set to 8 anywhere in the MP4 box hierarchy.

NO OTHER MEMORY SAFETY VULNERABILITIES found in `Ap4FileCopier.h`, `Ap4FileCopier.cpp`, or the directly invoked `AP4_Atom::Write` / `AP4_UnknownAtom::WriteFields` path.

---

## VULN: AP4_NullTerminatedStringAtom Heap OOB Write via Zero-Size String Atom
- **漏洞类别**: memory-safety
- **函数**: AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom()
- **行号**: 466-476 (Ap4Atom.cpp)
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_File::ParseStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:524-525, case AP4_ATOM_TYPE_8ID_] → new AP4_NullTerminatedStringAtom(type, size_64=8, stream) → constructor body: str_size=(AP4_UI32)8-8=0; str=new char[0]; str[0xFFFFFFFF]='\0'
- **描述**: 在 Ap4Atom.cpp:471 处，`str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE` 计算使用无符号 32 位算术（`AP4_Size = AP4_UI32`，`AP4_ATOM_HEADER_SIZE = 8`）。当 atom 的 size 字段恰好等于 8（即只有 header 无 payload）时，`str_size = 0`。后续在第 474 行 `str[str_size-1] = '\0'` 中，`str_size-1` 以 `AP4_UI32` 计算得 `0xFFFFFFFF`，导致将 `'\0'` 写入 `str + 0xFFFFFFFF` 这一远超堆缓冲区边界的地址，造成堆越界写。Ap4AtomFactory.cpp:215 的大小校验为 `size < 8` 才拒绝，size==8 通过检查，bug 路径可达。
- **触发条件**: 攻击者构造一个 MP4 文件，在 box 层次结构中任意位置放置一个四字节类型为 `8id ` (AP4_ATOM_TYPE_8ID_) 且 32 位 size 字段值恰好为 8 (0x00000008) 的 box，使 `AP4_AtomFactory` 以 size_64=8 调用 `AP4_NullTerminatedStringAtom` 构造函数。
- **安全影响**: 在 64 位系统上，`str[0xFFFFFFFF]` 访问非法地址，几乎必然触发 SIGSEGV 导致进程崩溃（DoS）。在 32 位地址空间中，`str + 0xFFFFFFFF` 可回绕到进程地址空间内的可控区域，存在被利用实现任意堆内存写从而达到远程代码执行（RCE）的可能性。

<!-- AUDIT_PROMPT_VERSION: 1 -->
