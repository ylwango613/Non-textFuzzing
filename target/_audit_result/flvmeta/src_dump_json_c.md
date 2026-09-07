I now have a complete picture of all relevant code. Let me do the final systematic pass across all confirmed call paths before writing the report.

**Batch 1 — AMF string allocation (amf.c:274-301, 906-927):**
- `amf_string_read`: reads `uint16_be` length (max 65535), calls `calloc(strsize, 1)` → fine.
- `amf_string_new(buf, size)`: calls `calloc(size+1, sizeof(byte))`. `size` is `uint16`; C integer promotion makes `size+1` an `int` (max 65536). No overflow on 32/64-bit targets.

**Batch 2 — AMF array/object count (amf.c:414-450):**
- `amf_array_read`: reads `uint32 array_size`, loops up to 4B times. Each iteration reads ≥1 byte from file; when file exhausts, `AMF_ERROR_EOF` exits the loop cleanly. malloc failures are caught and propagated. No memory corruption, only bounded DoS.

**Batch 3 — Date formatting (dump_json.c:85-86, amf.c:1166-1181):**
- `char str[128]` on stack; `strftime(buf, 128, "%Y-%m-%dT%H:%M:%S", t)` produces at most ~27 chars even for 64-bit extreme `time_t` (±292B year). `strftime` cannot fail with this format and `bufsize=128`. No stack overflow here.

**Batch 4 — `iscntrl(str[i])` in `json_print_string` (json.c:51):**
- `str[i]` is `char` (signed on x86). Bytes >127 → negative argument to `iscntrl`. UB per C standard. On glibc the table is offset-indexed (safe); on musl it's a pure computation (safe). Not exploitable on standard Linux targets.

**Batch 5 — `amf_object_delete` NULL dereference (amf.c:1012):**
- Immediately advances past first node before the NULL check, risking NULL deref. However, `amf_object_delete` is only called from the update path (`update.c`), not from any callback registered in `dump_json_file`. Not reachable via a crafted FLV in the read/dump mode.

**Batch 6 — Uncontrolled recursion in AMF parse + JSON dump (amf.c + dump_json.c) — CONFIRMED:**

`amf_data_read` (amf.c:466) dispatches to `amf_object_read` (amf.c:304) for type `0x03` (AMF_TYPE_OBJECT). Inside `amf_object_read`, `amf_data_read` is called recursively for each value:
```
amf_data_read → amf_object_read → amf_data_read → amf_object_read → ...
```
No recursion depth limit anywhere. After parsing, `json_amf_data_dump` (dump_json.c:53) similarly recurses:
```
json_amf_data_dump → (per value node) → json_amf_data_dump → ...
```
Each `json_amf_data_dump` frame allocates `char str[128]` (128 bytes) on the stack plus pointers (~176 bytes total per frame). At 50,000 nesting levels: ~8.8 MB of stack → exceeds the default 8 MB thread stack → SIGSEGV.

Required FLV payload: each nesting level needs 7 bytes of AMF encoding (1 type byte + 2-byte length + 1-byte key + inner value + 3-byte end marker). 50,000 levels = ~350 KB, well within the 16 MB max script tag body. This confirms external triggering via a crafted FLV file.

## VULN: Uncontrolled Recursion via Nested AMF Objects Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: `amf_data_read()` / `amf_object_read()` / `json_amf_data_dump()`
- **行号**: amf.c:466-500 (amf_data_read), amf.c:304-352 (amf_object_read), dump_json.c:30-93 (json_amf_data_dump)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: `flvmeta input.flv` → `dump_json_file()` → `flv_parse()` → `flv_read_metadata()` → `amf_data_file_read()` → `amf_data_read()` ↔ `amf_object_read()` (unbounded mutual recursion during parse); then `json_on_metadata_tag()` → `json_amf_data_dump()` → `json_amf_data_dump()` (unbounded self-recursion during JSON output)
- **描述**: `amf_data_read` (amf.c:479-481) calls `amf_object_read` for AMF type byte `0x03`; `amf_object_read` calls `amf_data_read` again for each object value (amf.c:325). Neither function imposes a recursion-depth limit. After parsing, `json_amf_data_dump` recurses for each child value (dump_json.c:53-55, 70, 79). Each `json_amf_data_dump` frame holds `char str[128]` plus pointer locals (~176 bytes). With deeply nested AMF objects, the cumulative stack usage exceeds the default 8 MB thread stack, causing a stack-based buffer overflow (SIGSEGV).
- **触发条件**: 攻击者构造一个 FLV 文件，其 script tag 的 AMF 数据中包含约 50,000 层嵌套的 AMF 对象（每层格式：`03 00 01 <key_byte> <nested_value> 00 00 09`），约需 350 KB AMF 数据，远小于 FLV script tag 的 16 MB 上限。
- **安全影响**: 进程因栈溢出崩溃（SIGSEGV），造成 Denial of Service。如果该工具被集成到服务器端自动化视频处理流水线中，任何能上传文件的用户均可远程触发服务崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
