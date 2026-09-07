### Heap Buffer Underwrite in `jas_icctxt_input` When `cnt` Is Zero (JasPer imginfo)

| 字段 | 值 |
|------|-----|
| **Severity** | High |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **CVSS v3.1** | 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | `jas_icctxt_input()` — `src/libjasper/base/jas_icc.c:1218` |

---

#### 漏洞描述 / Description

**中文**：当 JP2 文件嵌入的 ICC profile 中某 TXT 类型标签的 `len` 字段被设为 8 时，`jas_iccprof_load()` 计算得 `cnt = 0` 并传入 `jas_icctxt_input()`。该函数调用 `jas_malloc(0)` 获得非 NULL 指针后，在第 1218 行执行 `txt->string[cnt - 1] = '\0'`，即对 `txt->string[-1]` 写入一字节 `\0`，造成堆缓冲区向前越界写（heap underwrite），可破坏 glibc allocator 元数据或相邻堆对象，最终可能导致崩溃或被利用实现远程代码执行。

**English**: When a crafted JP2 file contains an ICC profile TXT-type tag with `len` set to 8, `jas_iccprof_load()` derives `cnt = 0` and passes it to `jas_icctxt_input()`. After `jas_malloc(0)` returns a non-NULL pointer, line 1218 writes `'\0'` to `txt->string[-1]`—one byte *before* the allocation boundary—corrupting glibc heap metadata or adjacent heap objects, with potential for crash (DoS) or exploitation leading to RCE.

---

#### 触发方式 / Trigger

```bash
# 构造含 len=8 TXT ICC 标签的 JP2 文件后执行：
imginfo -f crafted.jp2
```

调用链：`imginfo` → `jp2_decode()` → `jas_iccprof_createfrombuf()` → `jas_iccprof_load()` (`cnt=0`) → `jas_icctxt_input(attrval, in, 0)`

---

#### PoC 验证状态 / PoC Status

| 项目 | 内容 |
|------|------|
| **状态** | ✅ `VERIFIED_CRASH` |
| **PoC 编号** | 002 |
| **PoC 路径** | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_icc_c` |
