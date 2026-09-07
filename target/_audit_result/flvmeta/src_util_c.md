Now I have full context across all key files. Let me perform the detailed vulnerability analysis.

**Group 1 — `amf.c` lines 304–501: AMF recursive parsing**

`amf_data_read()` (line 466) dispatches to `amf_array_read()` (line 414), `amf_object_read()` (line 304), or `amf_associative_array_read()` (line 355). Each of those calls `amf_data_read()` recursively for every nested element. There is **no depth limit** anywhere. A crafted FLV with deeply nested arrays (`type=0x0A, count=1` repeated 40,000× = ~200 KB file) causes unbounded stack growth → stack overflow.

**Group 2 — `update.c` line 103: unchecked `malloc` in `write_flv()`**

```c
copy_buffer = (byte *)malloc(info->biggest_tag_body_size + FLV_TAG_SIZE);
```

`biggest_tag_body_size` is `uint32`, capped by the 24-bit FLV field at 0xFFFFFF (16 MB). No integer overflow. But there is **no NULL check**. If malloc fails (system memory pressure), `copy_buffer = NULL`. Then at line 208, `flv_read_tag_body(flv_in, copy_buffer, body_length)` passes NULL to `fread()` → NULL pointer dereference / crash. Also at lines 226 and 234.

**Group 3 — `check.c` line 659: unchecked `malloc` for message buffer**

```c
char * buffer = malloc(amf_string_get_size(name) + 50);
sprintf(buffer, "unknown metadata event name: '%s'", (char*)amf_string_get_bytes(name));
```

`amf_string_get_size(name)` returns `uint16` (max 65535). Allocation max 65585 bytes — no integer overflow. But again **no NULL check**. If malloc fails, `sprintf(NULL, ...)` is undefined behaviour / crash. Practical risk is low due to small allocation size, but the code path is reachable from any metadata tag whose name is not "onMetaData", "onCuePoint", or "onLastSecond".

**Verification check — `amf_string_new()` calloc(size+1)**

`size` is `uint16_t`; `size+1` is promoted to `int`, max 65536 — no integer overflow. `memcpy` copies `data->string_data.size` bytes into a `size+1`-byte buffer — correct. No heap overflow here.

**Verification check — `amf_array_read()` huge `array_size`**

`array_size = 0xFFFFFFFF` + file contains all null bytes: each `amf_data_read` → `amf_null_new()` → `malloc(sizeof(amf_data))`. OOM returns NULL, propagated correctly via `AMF_ERROR_NULL_POINTER`, loop exits cleanly. No heap corruption.

## VULN: Uncontrolled Recursion (Stack Overflow) in AMF Data Parser
- **漏洞类别**: memory-safety
- **函数**: amf_data_read(), amf_array_read(), amf_object_read(), amf_associative_array_read()
- **行号**: 414-450, 304-352, 355-411, 466-501
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → update_metadata() / check_flv_file() → get_flv_info() → flv_read_metadata() → amf_data_file_read() → amf_data_read() → amf_array_read() → amf_data_read() → amf_array_read() → … (unbounded mutual recursion)
- **描述**: `amf_data_read()`（amf.c:466）根据类型字节分发给 `amf_array_read()`、`amf_object_read()` 或 `amf_associative_array_read()`；这三个函数再次调用 `amf_data_read()` 解析每个子元素，形成无深度限制的相互递归。代码中没有任何递归深度计数器或上限检查，每层递归消耗若干字节的栈空间（局部变量 + 函数调用帧，约 80–200 字节）。当递归深度耗尽系统栈空间（Linux 默认 8 MB）时，触发栈溢出，导致进程崩溃（SIGSEGV）。
- **触发条件**: 攻击者构造一个 FLV 文件，其 Script tag 的 AMF 数据体包含深度嵌套的 AMF 数组或对象：重复写入 `0x0A 0x00 0x00 0x00 0x01`（单元素 strict_array）约 40,000 次，最后一字节 `0x05`（null）作为叶子。文件大小约 200 KB，无需任何特殊权限，传给 `flvmeta input.flv` 或 `flvmeta -U input.flv out.flv` 即可触发。
- **安全影响**: 确定性进程崩溃（DoS）。在未启用栈 canary 的编译环境下，攻击者通过精心控制 AMF 数据内容，可尝试将栈溢出转化为控制流劫持（RCE），但在带有 SSP/ASLR 的现代 Linux 上最坏情形为可靠 DoS。

## VULN: NULL Pointer Dereference from Unchecked malloc in write_flv()
- **漏洞类别**: memory-safety
- **函数**: write_flv()
- **行号**: 103-234
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 4.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → update_metadata() → write_flv() → malloc(info->biggest_tag_body_size + FLV_TAG_SIZE) [unchecked] → flv_read_tag_body(flv_in, NULL, body_length) → fread(NULL, …) → crash
- **描述**: `write_flv()`（update.c:103）使用 `info->biggest_tag_body_size`（第一遍扫描中记录的最大 tag body 长度，最大为 FLV 24 位字段上限 0xFFFFFF = 16 MB）调用 `malloc(info->biggest_tag_body_size + FLV_TAG_SIZE)`，但未对返回值进行 NULL 检查。若系统堆内存不足导致 malloc 返回 NULL，程序在第 208 行将 NULL 指针传入 `flv_read_tag_body()`，后者再将其传给 `fread(NULL, …)`，产生 NULL 指针解引用（未定义行为，在 Linux 上通常触发 SIGSEGV）。同一 NULL 指针还在第 226 行和第 234 行被传入 `fwrite()`。
- **触发条件**: 攻击者构造一个 FLV 文件，使某 tag 的 body_length 字段接近 0xFFFFFF（16 MB），同时在内存受限系统（如嵌入式设备、容器、低内存虚拟机）上运行 `flvmeta -U input.flv output.flv`，使 `malloc(~16 MB)` 失败并返回 NULL。
- **安全影响**: 进程崩溃（DoS）。在正常内存条件下不可触发；在内存受限环境中可通过精心构造 FLV 稳定复现。

## VULN: NULL Pointer Dereference from Unchecked malloc in check_flv_file()
- **漏洞类别**: memory-safety
- **函数**: check_flv_file()
- **行号**: 659-662
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 3.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L)
- **严重程度**: Low
- **攻击向量**: crafted FLV file
- **外部触发路径**: flvmeta main() → check_flv_file() → flv_read_metadata() → [AMF name parsed to unknown string] → malloc(amf_string_get_size(name) + 50) [unchecked, returns NULL] → sprintf(NULL, …) → crash
- **描述**: `check_flv_file()`（check.c:659）在遇到非标准 metadata 名称时，动态分配消息缓冲区 `malloc(amf_string_get_size(name) + 50)`（最大 65585 字节），但未检查返回值是否为 NULL。若 malloc 失败，随即调用 `sprintf(NULL, "unknown metadata event name: '%s'", …)` 造成 NULL 指针解引用，进程崩溃。触发路径：FLV Script tag 中 AMF 字符串 name 不属于 "onMetaData"/"onCuePoint"/"onLastSecond"，且系统恰好在此次分配时 OOM。
- **触发条件**: FLV 文件包含一个 Script tag，其 AMF name 字段为任意非标准字符串（如长度 65535 字节的随机内容），同时系统处于内存紧张状态导致 malloc（最多 65585 字节）失败。由于分配体量较小，实际可利用性极低，仅在高内存压力下可重现。
- **安全影响**: 进程崩溃（DoS）。仅在系统 OOM 条件下可触发，实际风险较低。

<!-- AUDIT_PROMPT_VERSION: 1 -->
