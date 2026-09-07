The analysis is complete. The vulnerability is confirmed with no guard in the call chain. Here is the final audit report:

## VULN: AP4_RtpAtom signed-integer underflow → heap buffer overflow via stream.Read
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpAtom::AP4_RtpAtom()
- **行号**: 47-51
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → Ap4AtomFactory.cpp:644 AP4_RtpAtom::Create(size_32, stream) → AP4_RtpAtom::AP4_RtpAtom(size, stream) → line 47 str_size underflow → line 49 new char[0] → line 50 stream.Read(str, 0xFFFFFFFF)
- **描述**: `size` 是从 MP4 文件头直接读取的 `AP4_UI32`（无符号32位）。第47行计算 `int str_size = size-(AP4_ATOM_HEADER_SIZE+4)` 即 `size - 12`，均为无符号运算。当攻击者将 `rtp ` atom 的 size 字段设为 11 时，`11u - 12u = 0xFFFFFFFF`（AP4_UI32 回绕），赋值给 `int str_size` 得到 -1。第48行 `if (str_size)` 条件为真（-1 ≠ 0），进入块内。第49行 `new char[str_size+1]` = `new char[0]`，合法分配0字节缓冲区，返回非空指针。第50行 `stream.Read(str, str_size)` 将 `int -1` 隐式转换为 `AP4_Size`（即 `AP4_UI32`） = `0xFFFFFFFF` = 4,294,967,295，随即向0字节缓冲区写入最多约4 GB数据，造成堆缓冲区溢出。第51行 `str[str_size]` = `str[-1]` 也是越界写（OOB write at -1 offset）。
- **触发条件**: 构造一个包含 `rtp ` atom 的 MP4 文件，将该 atom 的4字节 big-endian size 字段设为 `0x0000000B`（11），之后跟随任意内容（可超过11字节）。Ap4AtomFactory.cpp:642-644 对 RTP_ atom 仅检查 `atom_is_large` 标志，无最小 size 校验，`size_32=11` 直接传入构造函数。
- **安全影响**: 攻击者控制堆上大量写入的内容（来自文件中紧随 atom 头之后的字节），可覆盖相邻堆块的元数据或对象指针，在最坏情况下实现任意代码执行（RCE）；即使不能完全控制写入内容，也可稳定触发进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
