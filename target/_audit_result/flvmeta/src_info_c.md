**Group 1 (lines 1–538 of info.c) analysis complete.** No direct malloc-arithmetic overflow found. Identified a dangerous `body_length - sizeof(flv_video_tag)` subtraction that can underflow but actual reads are bounded by the stream tracker. Key concern is the AMF parsing call chain from `flv_read_metadata`.

**Group 2 (amf.c, amf_data_read / amf_object_read / amf_array_read):** These functions are mutually recursive with **no recursion depth limit**. Each object value that is itself an object causes one additional frame: `amf_data_read` → `amf_object_read` → `amf_data_read` → … This is unbounded.

**avc.c analysis:** Line 242's bounds check `sps_size > body_length - 12` has an unsigned-integer underflow when `body_length < 12` (allowed by the entry guard at line 205 which requires only `body_length >= 10`). However, the subsequent `flv_read_tag_body` is bounded by `stream->current_tag_body_length`, so the check at line 251 (`< sps_size`) catches the short read before `parse_sps` is ever invoked. Not exploitable as a memory write.

**update.c line 103:** `malloc(info->biggest_tag_body_size + FLV_TAG_SIZE)` — `biggest_tag_body_size` is bounded to 24-bit (max 0xFFFFFF), no integer overflow in the malloc argument. The missing NULL check afterwards is a hardening issue but not reachable with a crafted file (malloc of 16MB should not fail).

**Confirmed exploitable memory safety issue:** The recursive AMF parsing with no depth limit. A crafted FLV script tag with deeply nested AMF objects (each level only costs ~6 bytes) can overflow the stack. At ~130 bytes/frame and 8MB default stack, ~60,000 levels suffice; a sub-MB file can embed 100,000+ nesting levels.

## VULN: Stack Overflow via Unbounded Recursive AMF Object Parsing
- **漏洞类别**: memory-safety
- **函数**: amf_data_read() / amf_object_read() / amf_associative_array_read()
- **行号**: amf.c:304-352 (amf_object_read), amf.c:355-411 (amf_associative_array_read), amf.c:466-501 (amf_data_read)
- **CWE**: CWE-674 (Uncontrolled Recursion) → CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → update_metadata() / check_flv_file() → get_flv_info() → flv_read_metadata() (flv.c:274) → amf_data_file_read() → amf_data_read() → amf_object_read() → amf_data_read() [unbounded mutual recursion]
- **描述**: `amf_data_read()` (amf.c:466) dispatches on the AMF type byte; for `AMF_TYPE_OBJECT` (0x03) and `AMF_TYPE_ASSOCIATIVE_ARRAY` (0x08) it calls `amf_object_read()` / `amf_associative_array_read()`, each of which calls `amf_data_read()` again for every value element (amf.c:325, amf.c:383). There is no recursion depth counter, no maximum depth check, and no iterative re-implementation. Every level of nested AMF object burns one additional C call frame on the stack. When nesting is sufficiently deep the program writes past the end of the thread stack, corrupting adjacent memory (guard page absent) or triggering SIGSEGV/SIGBUS on guard-page architectures.
- **触发条件**: 构造一个 FLV 文件，其 Script tag（type=0x12）的 AMF 数据体为超深嵌套的 AMF object：每层约 6 字节（`\x03` type + 2-byte 空 key + 子对象 type + 末尾 `\x00\x00\x09` terminator），约 60,000 层嵌套即可在 8MB 默认栈的 Linux 系统上触发栈溢出；整个 payload 大小不到 360KB，远小于 FLV tag 最大 24-bit body_length（16MB）。
- **安全影响**: 在拥有 stack guard page 的现代系统上可靠地导致程序崩溃（DoS）。在无 guard page 或自定义栈配置的环境（嵌入式、FFmpeg 插件宿主、批量处理服务等）中，stack smashing 可能覆盖邻近帧的返回地址，进而实现任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
