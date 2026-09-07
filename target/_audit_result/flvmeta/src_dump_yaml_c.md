Now I have a full picture of the code. Let me consolidate my findings into the required format.

**Batch 1 (dump_yaml.c direct):** `str[128]` buffers, sprintf bounds — all safe. YAML string path passes `uint16` size cast to `int` — fine.

**Batch 2 (amf.c reading):** `amf_string_read` uses `uint16_be strsize` → `calloc(strsize, 1)` max 65535 bytes — no overflow. `amf_string_new` calls `calloc(size+1, 1)` where `size` is `uint16` so `size+1` is at most 65536 — no overflow after integer promotion. Array/object loops exit on EOF — no out-of-bounds.

**Batch 3 (recursion):** `amf_data_read` → `amf_array_read` → `amf_data_read` (for each element) is **unbounded** — no depth limit. Similarly, `amf_data_yaml_dump` → (per-element call) → `amf_data_yaml_dump` is **unbounded**. The YAML dump frame includes `char str[128]` + `yaml_event_t event` (~80 bytes in libyaml) ≈ 250–300 bytes/frame. With a Linux 8 MB stack: only ~27 000–33 000 levels before overflow. The reading frame is ~100–130 bytes, so up to ~65 000–83 000 levels fit. A file with nesting depth ≈ 50 000 is read without crashing but **crashes** during YAML output.

**Batch 4 (update.c / info.c):** `biggest_tag_body_size` is bounded by 24 bits (FLV tag body_length field), so `malloc(biggest_tag_body_size + FLV_TAG_SIZE)` cannot overflow. No heap overflow there.

**Batch 5 (yaml_on_tag buffer):** `sprintf(buffer, "%llu", (long long)off_t)` — max positive `off_t` = LLONG_MAX = 19 decimal digits + '\0' = 20 bytes, exactly fills `buffer[20]`; safe for normal files.

The only confirmed memory-safety vulnerabilities are the two manifestations of unbounded recursion.

## VULN: Stack overflow via unbounded recursion in AMF parsing (amf_data_read)
- **漏洞类别**: memory-safety
- **函数**: amf_data_read() / amf_array_read() / amf_object_read()
- **行号**: amf.c:414-450 (amf_array_read), amf.c:466-501 (amf_data_read), amf.c:304-352 (amf_object_read)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → flv_parse() → flv_read_metadata() → amf_data_file_read() → amf_data_read() → amf_array_read() → (loop) → amf_data_read() → amf_array_read() → ... [unbounded mutual recursion]
- **描述**: `amf_data_read` dispatches on AMF type and calls type-specific readers; `amf_array_read` and `amf_object_read` each call `amf_data_read` for every element they contain. There is no recursion depth limit anywhere in the chain. Each combined call frame (`amf_data_read` + `amf_array_read`) occupies approximately 100–150 bytes of stack. With a default Linux stack of 8 MB, ~55 000–83 000 levels exhaust the stack, causing a SIGSEGV.
- **触发条件**: 攻击者构造一个 FLV 文件，其 script 标签的 AMF payload 为一条深度嵌套的 strict-array 链（每个 array 的 count 字段为 1，唯一元素为下一个 array），嵌套深度约 60 000–80 000 层，对应 AMF payload 约 300–400 KB（每层仅需 1 字节类型 + 4 字节 count = 5 字节），整体嵌入合法 FLV script tag（24 位 body_length 最大 16 MB，可容纳该 payload）。
- **安全影响**: 进程因栈溢出收到 SIGSEGV 崩溃（DoS）；在栈保护机制缺失或可控的环境下，理论上可进一步演变为代码执行。

## VULN: Stack overflow via unbounded recursion in YAML AMF dump
- **漏洞类别**: memory-safety
- **函数**: amf_data_yaml_dump()
- **行号**: dump_yaml.c:30-111 (amf_data_yaml_dump，特别是第 95、61、83 行的递归调用)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → dump_yaml_file() → flv_parse() → yaml_on_metadata_tag() → amf_data_yaml_dump(array_data) → [while loop, line 95] → amf_data_yaml_dump(nested_array) → [while loop] → amf_data_yaml_dump(nested_nested_array) → ... [unbounded]
- **描述**: `amf_data_yaml_dump` 对 AMF_TYPE_ARRAY 和 AMF_TYPE_OBJECT / AMF_TYPE_ASSOCIATIVE_ARRAY 分支均通过 `while` 循环对每个子元素递归调用自身（第 61、83、95 行），没有深度上限。该函数栈帧较大：含 `char str[128]`（128 字节）加 `yaml_event_t event`（libyaml 中约 80–100 字节），合计每帧约 250–300 字节。8 MB 栈仅能容纳约 27 000–33 000 帧。相比之下，读取阶段（amf_data_read）帧约 100–130 字节，同一深度的嵌套结构可以被读入内存而不崩溃，随后在 YAML 输出阶段触发栈溢出。嵌套深度约 40 000–50 000 层即可在读取通过后于 dump 阶段产生崩溃，所需文件约 200–250 KB。
- **触发条件**: 攻击者构造一个 FLV script 标签，其 AMF payload 为深度约 50 000 层的 strict-array 单元素链（每层 5 字节），整体约 250 KB，嵌入合法 FLV 文件后以 `flvmeta file.flv` 或 `flvmeta --dump-format yaml file.flv` 触发。读取阶段（amf_data_read 帧约 130 B/层，50000 层共约 6.5 MB）在 8 MB 栈内通过，YAML 输出阶段（amf_data_yaml_dump 帧约 300 B/层，50000 层共约 15 MB）溢出栈。
- **安全影响**: 进程在 `amf_data_yaml_dump` 调用链中因栈溢出收到 SIGSEGV 崩溃（DoS）；若 flvmeta 用于自动化处理用户上传的 FLV 文件（如媒体服务器流水线），攻击者可以此实现远程拒绝服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
