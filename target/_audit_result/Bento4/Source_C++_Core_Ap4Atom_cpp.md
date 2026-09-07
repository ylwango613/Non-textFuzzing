**Analysis complete.** `AP4_Size` is `AP4_UI32`. The vulnerability at line 470–473 is fully confirmed:

- `str_size = (AP4_Size)8 − 8 = 0` (unsigned, no wrap)
- `new char[0]` returns valid non-null pointer (C++ standard)
- `str[str_size−1]` = `str[0xFFFFFFFF]` → write ~4 GB past allocation → SIGSEGV (DoS); on 32-bit, wraps to `str−1` (heap metadata corruption → potential RCE)

Call chain: `mp42aac` → `AP4_File(stream)` → `AP4_DefaultAtomFactory::CreateAtomFromStream` → `case AP4_ATOM_TYPE_8ID_:` (Ap4AtomFactory.cpp:525) → `new AP4_NullTerminatedStringAtom(type, 8, stream)` → crash at Ap4Atom.cpp:473.

---

## VULN: Heap OOB Write in AP4_NullTerminatedStringAtom When Atom Size == Header Size
- **漏洞类别**: memory-safety
- **函数**: AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(AP4_Atom::Type, AP4_UI64, AP4_ByteStream&)
- **行号**: 470-473
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(stream) → AP4_DefaultAtomFactory::CreateAtomFromStream (Ap4AtomFactory.cpp:139) → AP4_AtomFactory::CreateAtomFromStream(stream, type, size_32, size_64, atom) (Ap4AtomFactory.cpp:257) → case AP4_ATOM_TYPE_8ID_: new AP4_NullTerminatedStringAtom(type, size_64=8, stream) (Ap4AtomFactory.cpp:525) → AP4_NullTerminatedStringAtom constructor (Ap4Atom.cpp:466) → str[str_size-1] (Ap4Atom.cpp:473)
- **描述**: 在 `AP4_NullTerminatedStringAtom` 的流读取构造函数中，`str_size` 通过 `(AP4_Size)size - AP4_ATOM_HEADER_SIZE` 计算（均为 AP4_UI32，即无符号32位）。当 atom 的 `size` 字段恰好等于 `AP4_ATOM_HEADER_SIZE`（8字节，即只有头部、无 payload）时，`str_size = 0`。随后 `new char[0]` 返回合法非空指针 `str`，`stream.Read(str, 0)` 无写入，但紧接着 `str[str_size-1]` = `str[(AP4_UI32)0 - 1]` = `str[0xFFFFFFFF]`，在64位系统上对 `str + 4294967295` 地址执行单字节写 `'\0'`，该地址必然超出已映射内存；在32位系统上则等同于 `str[-1]`，写入堆块头部前一字节，可破坏堆元数据。atom size 字段完全来自文件，工厂仅检查 `size < 8` 时拒绝（Ap4AtomFactory.cpp:215），`size == 8` 通过验证后直接传入构造函数，无任何额外防护。
- **触发条件**: 在 MP4 文件任意嵌套层级中嵌入类型为 `8ID_`（四字节：`0x38 0x69 0x64 0x5F`）、size 字段为 `0x00000008` 的 atom 即可触发。攻击者仅需修改合法 MP4 文件，在其 moov 或任意容器 atom 内插入该8字节 atom；`AP4_DefaultAtomFactory` 无条件处理 `8ID_` 类型（不需要 Marlin DRM 标志）。
- **安全影响**: 在64位系统上程序以 SIGSEGV 崩溃（可靠 DoS）；在32位系统上越界写 `str[-1]` 破坏相邻堆元数据，配合精心布局可转化为任意代码执行（RCE）。最坏情况下攻击者通过令受害者处理恶意 MP4 文件获得 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
