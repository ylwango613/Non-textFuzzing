Based on my thorough analysis of `dump_raw.c` and all its transitively called code (`amf.c`, `flv.c`, `info.c`, `update.c`, `avc.c`, `check.c`, types, headers), I have traced every malloc, calloc, memcpy, recursion, and sprintf call for memory safety issues. Here are my confirmed findings:

**Group 1 – Parsing recursion (amf.c `amf_object_read` / `amf_array_read`):** AMF objects and arrays are parsed with mutually recursive calls between `amf_data_read` (line 466) and `amf_object_read` (line 304) / `amf_array_read` (line 414). There is no nesting depth limit, so a crafted FLV with arbitrarily nested AMF structures exhausts the call stack.

**Group 2 – Dump recursion (amf.c `amf_data_dump`):** Called directly from `raw_on_metadata_tag()` at `dump_raw.c:124`. Each AMF object/array node recurses with `indent_level+1`. The frame allocates a 128-byte `char datestr[128]` local buffer, making it more stack-hungry than the parse frames and reachable at a shallower nesting depth.

**All other sites checked and found safe:** Every `malloc`/`calloc` size is bounded (string lengths by `uint16`≤65535, tag body by `uint24`≤16 MB); memcpy destinations are always exactly sized; `sprintf` buffers in `check.c` use only fixed-width numeric/type-name substitutions that fit within 256 bytes; the AVC `sps_size` underflow path still results in a bounded read that is caught by EOF detection in `flv_read_tag_body`; `copy_buffer` in `update.c` is bounded to ≤16 MB so the missing NULL check is not attacker-reachable under normal conditions.

---

## VULN: Uncontrolled Recursion in amf_data_read Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: amf_data_read() / amf_object_read() / amf_array_read()
- **行号**: 303-352 (amf_object_read), 413-450 (amf_array_read), 466-500 (amf_data_read)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() -> dump_raw_file() -> flv_parse() -> [FLV_TAG_TYPE_META] -> flv_read_metadata() -> amf_data_file_read() -> amf_data_read() -> amf_object_read() -> amf_data_read() -> amf_object_read() -> ... (unbounded)
- **描述**: `amf_data_read()` and `amf_object_read()` are mutually recursive with no depth limit. `amf_object_read` loops calling `amf_data_read` for each object value (line 325), and `amf_data_read` dispatches back to `amf_object_read` (line 479) or `amf_array_read` (line 489) for nested containers. `amf_array_read` similarly calls `amf_data_read` inside a loop (line 434). There is no maximum nesting counter anywhere in the chain. Each pair of nested frames consumes stack space for local pointers and error codes, and the recursion continues until the stack segment is exhausted, producing a SIGSEGV.
- **触发条件**: 攻击者构造一个 FLV 文件，其 Script Tag 中包含深度嵌套的 AMF object（类型字节 0x03）或 strict array（0x0A），每层嵌套最少需要 3 字节（1B 类型 + 2B 空字符串名 + 1B 值类型）。在典型 8MB 栈上，约 10 000–50 000 层嵌套即可使栈耗尽。
- **安全影响**: 程序因 stack exhaustion 产生 SIGSEGV（DoS）；在关闭栈金丝雀的构建中，精心对齐的嵌套可能覆盖返回地址，进而可能实现 RCE。

## VULN: Uncontrolled Recursion in amf_data_dump Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: amf_data_dump()
- **行号**: 788-856 (amf.c), triggered from dump_raw.c:124
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() -> dump_raw_file() -> flv_parse() -> raw_on_metadata_tag() (dump_raw.c:124) -> amf_data_dump(stdout, data, 0) -> amf_data_dump(..., indent_level+1) -> amf_data_dump(..., indent_level+2) -> ... (unbounded)
- **描述**: `amf_data_dump()` recurses with `indent_level+1` for every nested AMF object member (lines 808, 810) and every array element (line 840). There is no recursion depth limit. Critically, each stack frame allocates a 128-byte local array `char datestr[128]` (line 791) regardless of whether a date is present. This makes each frame substantially larger than during parsing, so the stack is exhausted at a shallower nesting depth than in the parse phase. The recursion is driven entirely by attacker-controlled structure in the FLV file's script tag.
- **触发条件**: 攻击者构造一个 FLV 文件，其 Script Tag 中的 AMF object 或 array 具有数千层嵌套。由于每帧含 128 字节 `datestr` 数组，约 4 000–8 000 层嵌套在 1–8MB 栈上即可触发 stack exhaustion。
- **安全影响**: 程序因 stack exhaustion 产生 SIGSEGV（DoS）；在禁用栈保护的构建中，返回地址覆盖潜在可导致 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
