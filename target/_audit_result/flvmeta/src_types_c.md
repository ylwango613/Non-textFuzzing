I now have a complete picture. Let me compile my analysis findings before writing the final report.

**Group 1 — `types.c` itself**: Only byte-swap helpers and Win32 seek wrappers. No allocations, no external data. Clean.

**Group 2 — `amf.c` (lines 1–601)**: `amf_string_read` reads `uint16_be` size, then `calloc(strsize, 1)` + `amf_string_new(buffer, strsize)` which calls `calloc(size+1, 1)`. With `size` as `uint16` (max 65535), `size+1` is promoted to `int` = 65536 — no overflow on any modern 32-bit-or-wider int platform. `amf_array_read` reads `uint32` array_size from file but each iteration reads from the actual file stream, terminating on EOF. No direct heap overflow.

**Key finding — amf.c lines 304–501**: `amf_data_read` dispatches to `amf_object_read`, `amf_associative_array_read`, and `amf_array_read`. Each of these calls `amf_data_read` recursively for element values. **No recursion depth limit exists.** An attacker crafts a Script tag with a chain of deeply nested AMF objects (each object containing one key whose value is another object, etc.). At ~4 bytes per nesting level vs. a 16 MB tag body, the attacker can induce ~4 million nesting levels. Stack overflow occurs in the ~80,000–200,000 range depending on platform frame size, well within budget. The same vulnerability applies to the subsequent `amf_data_size()`, `amf_data_free()`, and `amf_data_clone()` calls that are also recursive without depth limits.

**Group 3 — `amf.c` (lines 601–1182)**: `amf_object_delete` has a NULL-pointer dereference bug (`node = node->next` then `node->data` without NULL check at line 1016), but this function is **never called anywhere** in the codebase (confirmed by grep — only its definition appears). Not externally exploitable.

**Group 4 — `avc.c`**: `sps_size` is `uint16` (max 65535), `malloc(sps_size)` is safe. The `body_length - 12` bounds check can underflow when `body_length < 12` (due to `sizeof(flv_video_tag)` mismatch with actually-consumed bytes in info.c:433), but this only causes the check to be bypassed — actual reads via `flv_read_tag_body` are bounded by the stream state machine. No heap overflow.

**Group 5 — `update.c`**: `malloc(biggest_tag_body_size + FLV_TAG_SIZE)` has no NULL check (line 103). Exploitable only under OOM, not via file content alone; `biggest_tag_body_size` is bounded by the 24-bit tag field (max 16 MB), making OOM unlikely via normal system conditions. Not file-controllable.

**Group 6 — `flv.c`, `info.c`, `check.c`**: Reads use `flv_read_tag_body` which correctly clamps against `current_tag_body_length`. All integer accumulations use `file_offset_t` (64-bit). No heap overflow found.

---

## VULN: Uncontrolled AMF object recursion causes stack overflow
- **漏洞类别**: memory-safety
- **函数**: `amf_data_read()` / `amf_object_read()` / `amf_associative_array_read()` / `amf_array_read()`
- **行号**: amf.c:304-352 (amf_object_read), amf.c:355-411 (amf_associative_array_read), amf.c:414-450 (amf_array_read), amf.c:466-501 (amf_data_read)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted FLV file
- **外部触发路径**: `flvmeta main()` → `flv_parse()` / `get_flv_info()` → `flv_read_metadata()` → `amf_data_file_read()` → `amf_data_read()` → `amf_object_read()` → `amf_data_read()` → `amf_object_read()` → … (无限递归直到栈溢出)
- **描述**: `amf_data_read`（amf.c:466）根据 AMF 类型字节分发到 `amf_object_read`/`amf_associative_array_read`/`amf_array_read`，这三个函数在解析每个元素值时又无条件回调 `amf_data_read`，形成无深度限制的相互递归。递归栈帧约占 80–120 字节；当嵌套深度达到约 80,000–100,000 层（所需 AMF 数据约 320–400 KB，远低于 FLV 标签体最大值 16 MB）时，栈空间（默认 8 MB）耗尽，导致栈溢出（SIGSEGV 或栈内存越界写）。此外，解析完成后调用的 `amf_data_size()`（amf.c:504）和 `amf_data_free()`（amf.c:762）同样对已解析的深层嵌套对象进行相同深度的递归，同样触发栈溢出。
- **触发条件**: 攻击者构造一个 FLV 文件，其 Script 标签（type=0x12）的 AMF 负载包含深度嵌套的 AMF Object（0x03）或 AMF Array（0x0A）结构，例如 N 层 `{0x03, 0x00,0x01,"a", [递归内容], 0x00,0x00,0x09}`，每层仅需约 4 字节，总共约 320 KB 即可使典型 Linux 系统（8 MB 默认栈）的栈溢出。
- **安全影响**: 确定造成进程崩溃（DoS）；在线程栈相邻堆/其他线程栈的内存布局下，栈溢出可覆盖相邻内存区域，理论上可升级为任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
