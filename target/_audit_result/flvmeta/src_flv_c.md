Based on my thorough analysis of all relevant source files (flv.c, amf.c, update.c, check.c, info.c, avc.c, bitstream.c), I have identified the following memory safety vulnerabilities:

**Analysis summary by component:**
- `amf.c`: AMF string reads use uint16 length → calloc properly sized; array count reads (uint32) but loop exits on EOF; error paths handled correctly
- `flv.c`: Tag body reads bounded by `current_tag_body_length`; no overflow
- `info.c`: `biggest_tag_body_size` set from 3-byte field (max 0xFFFFFF); `amf_data_size()` returns size_t
- `update.c:103`: `malloc(biggest_tag_body_size + FLV_TAG_SIZE)` — **no NULL check**, then unconditional use
- `check.c:659`: `malloc(amf_string_get_size(name) + 50)` — **no NULL check**, then sprintf to potentially-NULL buffer
- `avc.c:242`: `sps_size > body_length - 12` with body_length possibly 10–11 causes unsigned underflow in check, but actual read is bounded by `flv_read_tag_body` stream clamping
- `bitstream.c`: `skip_bits` advances pointer without bounds checking, but `get_bit` guards subsequent reads with a bounds check

## VULN: NULL Pointer Dereference via Unchecked malloc in write_flv
- **漏洞类别**: memory-safety
- **函数**: write_flv()
- **行号**: 103-208
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() -> update_metadata() -> write_flv() -> malloc(info->biggest_tag_body_size + FLV_TAG_SIZE) [line 103] → (no NULL check) → flv_read_tag_body(flv_in, copy_buffer=NULL, body_length) [line 208] → fread(NULL, 1, body_length, stream->flvin) → NULL dereference
- **描述**: `write_flv()` 在 update.c 第 103 行调用 `malloc(info->biggest_tag_body_size + FLV_TAG_SIZE)` 后未检查返回值是否为 NULL。当 malloc 失败时，`copy_buffer` 为 NULL，随后在第 208 行调用 `flv_read_tag_body(flv_in, copy_buffer, body_length)`，该函数内部调用 `fread(NULL, 1, bytes_number, stream->flvin)`，触发 NULL 指针解引用，导致程序崩溃。`biggest_tag_body_size` 最大为 0xFFFFFF（来自 FLV tag 3字节 body_length 字段），意味着 malloc 可申请高达 16MB 内存，在内存受限环境下可能失败。
- **触发条件**: 攻击者构造含有大 body_length 的 FLV tag（如视频/音频 tag，body_length 接近 0xFFFFFF），使 `biggest_tag_body_size` 尽可能大；在内存受限系统（如低内存 ulimit 限制）下，使用 `flvmeta -U input.flv output.flv` 命令触发 write_flv，导致 malloc(~16MB) 失败，NULL 指针被传入 fread。
- **安全影响**: 程序崩溃（DoS）。在极端情况下，若 malloc(0) 返回非 NULL 小块而后续 body_length 非 0 时，可能写入越界内存。

## VULN: NULL Pointer Dereference via Unchecked malloc in check_flv_file
- **漏洞类别**: memory-safety
- **函数**: check_flv_file()
- **行号**: 659-661
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() -> check_flv_file() -> flv_read_metadata() -> amf_data_file_read() [解析 AMF 元数据名] -> check_flv_file() line 659: malloc(amf_string_get_size(name) + 50) [无 NULL 检查] -> sprintf(buffer=NULL, ...) -> NULL 指针写入 -> 崩溃
- **描述**: `check_flv_file()` 在 check.c 第 659 行分配动态缓冲区 `char * buffer = malloc(amf_string_get_size(name) + 50)` 用于格式化未知元数据名称的消息，但**未检查 malloc 返回值**。若 malloc 失败返回 NULL，第 661 行 `sprintf(buffer, "unknown metadata event name: '%s'", ...)` 将向 NULL 指针写入，引发空指针解引用导致程序崩溃。该代码路径由 FLV script tag 中任意非 "onMetaData"/"onCuePoint"/"onLastSecond" 名称触发（任意自定义名称均可）。
- **触发条件**: 构造一个 FLV 文件，其中包含 script tag，AMF 元数据名称字段设置为任意非标准字符串（如 "onFoo"），并在内存受限的环境下执行 `flvmeta --check input.flv`，使 malloc 在处理未知名称时失败。
- **安全影响**: 程序崩溃（DoS）。在特殊内存布局下（如 ptmalloc 调试模式、自定义 malloc 实现）可能进一步导致任意内存写入。

<!-- AUDIT_PROMPT_VERSION: 1 -->
