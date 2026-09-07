I have all the information needed. Let me do a final verification of the key arithmetic:

- `AP4_ATOM_HEADER_SIZE` = 8 (const `AP4_UI32`)
- `size` is `AP4_UI32`
- `int str_size = size-(AP4_ATOM_HEADER_SIZE+4)` → unsigned subtraction, result assigned to **signed** `int`
- If `size == 11`: `11u - 12u` = `0xFFFFFFFF` → cast to `int` = `-1`
- `if (str_size)` → `-1` ≠ 0 → **true** (the guard does NOT protect against negative values)
- `new char[str_size+1]` = `new char[-1+1]` = `new char[0]` → **0-byte allocation succeeds**
- `stream.Read(str, str_size)` where `str_size=-1` passed to param typed `AP4_Size` (`AP4_UI32`) → implicit conversion to **`0xFFFFFFFF`** → attempts to read 4GB into 0-byte buffer → **heap buffer overflow**

Factory at line 642–644 has no minimum-size guard before calling `AP4_RtpAtom::Create(size_32, stream)`.

## VULN: Integer Underflow in AP4_RtpAtom Constructor Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpAtom::AP4_RtpAtom()
- **行号**: 47-54 (Ap4RtpAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() [Ap4AtomFactory.cpp:642-644] → AP4_RtpAtom::Create(size_32=11, stream) → AP4_RtpAtom::AP4_RtpAtom(size=11, stream) [Ap4RtpAtom.cpp:47-54]
- **描述**: 在 `AP4_RtpAtom` 构造函数第 47 行，`str_size` 被声明为 `int`（有符号整数），但其值由无符号减法 `size-(AP4_ATOM_HEADER_SIZE+4)` 即 `(AP4_UI32)size - 12u` 计算而来。当 `size==11`（攻击者在 MP4 文件中写入的 box size 字段）时，`11u - 12u` 发生无符号下溢，结果为 `0xFFFFFFFF`，赋值给 `int` 后得到 `-1`。第 48 行的防护条件 `if (str_size)` 对非零值为真，`-1` 满足条件进入分支。第 49 行 `new char[str_size+1]` = `new char[-1+1]` = `new char[0]`，在 C++ 中合法，分配一个 0 字节的堆块并返回非空指针。第 50 行 `stream.Read(str, str_size)` 中 `str_size`（值为 `-1`，类型 `int`）被隐式转换为 `AP4_Size`（即 `AP4_UI32`），变为 `0xFFFFFFFF`（约 4GB），导致函数向仅 0 字节大小的堆缓冲区写入大量从 stream 读出的数据，形成堆缓冲区溢出。
- **触发条件**: 攻击者构造一个 MP4 文件，其中包含一个 `rtp ` 类型的 box，将其 size 字段（文件偏移量 0-3 处的大端 32 位整数）设置为 `11`。工厂代码（Ap4AtomFactory.cpp 第 642-644 行）仅检查 `atom_is_large` 而未对 `size_32 >= 12` 做最小值校验，因此 `size_32=11` 被直接传入构造函数触发漏洞。
- **安全影响**: 堆缓冲区溢出可覆盖堆元数据或相邻堆块内容，最坏情况可被利用实现远程代码执行（RCE）；即使无法控制利用方向，也会导致程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
