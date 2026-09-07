Now I have complete context. Let me analyze the full picture:

**Analysis of `tif_warning.c` (82 lines):**

`TIFFWarning` (lines 51-60) and `TIFFWarningExt` (lines 63-72) both call `va_start(ap, fmt)` once, then conditionally invoke `_TIFFwarningHandler(module, fmt, ap)` followed by `_TIFFwarningHandlerExt(..., fmt, ap)` — passing the **same `va_list ap`** to both.

The default Unix handler (`unixWarningHandler` in tif_unix.c:275-280) calls `vfprintf(stderr, fmt, ap)`, which **consumes and advances** `ap` through all variadic arguments. Per C11 §7.16.1p3: after `ap` is passed to a function that uses `va_arg` internally, `ap` is in an indeterminate state and must not be reused without `va_start`/`va_copy`.

If an application also installs `_TIFFwarningHandlerExt` (non-NULL), the second handler at line 58/70 receives the already-exhausted `ap`. Any `vfprintf`/`vprintf` call inside that second handler will call `va_arg` on the stale `va_list`, reading from indeterminate stack memory — an OOB read. On x86-64, the `__va_list_tag` struct's `overflow_arg_area` pointer will be advanced past the frame's actual overflow arguments, causing reads from arbitrary stack offsets.

The same bug exists symmetrically in `tif_error.c` lines 55-58 and 67-70.

**Triggering from a crafted TIFF:** Any TIFF that causes a warning during parsing (e.g., unsupported photometric, missing required tag, malformed IFD) will invoke `TIFFWarning`/`TIFFWarningExt`. When an application has installed both handlers (a documented use case for per-file error routing via the `thandle_t` parameter), the double va_list use fires. The crafted TIFF file controls whether warnings are generated.

**Severity assessment:** The bug requires `_TIFFwarningHandlerExt` to be non-NULL (not the library default, but explicitly set by the application). The OOB read reads from stack memory after the variadic argument area — leading to information disclosure or process crash. No RCE is expected since format strings are library-controlled, not attacker-controlled TIFF content.

## VULN: Double va_list Use After Consumption in TIFFWarning / TIFFWarningExt
- **漏洞类别**: memory-safety
- **函数**: TIFFWarning(), TIFFWarningExt()
- **行号**: 50-72
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() -> TIFFOpen() -> TIFFReadDirectory() -> TIFFWarning()/TIFFWarningExt() -> [_TIFFwarningHandler consumes va_list via vfprintf] -> _TIFFwarningHandlerExt called with exhausted va_list -> second handler calls vfprintf(fmt, ap) -> OOB read from stack
- **描述**: 在 `TIFFWarning`（tif_warning.c:51-60）和 `TIFFWarningExt`（tif_warning.c:63-72）中，`va_list ap` 经 `va_start` 初始化后，先被传入 `_TIFFwarningHandler`（默认实现 `unixWarningHandler` 内部调用 `vfprintf(stderr, fmt, ap)` 完全消耗并推进 `ap`），之后又在未调用 `va_end`/`va_start`/`va_copy` 的情况下再次传入 `_TIFFwarningHandlerExt`。C11 §7.16.1p3 明确规定，`va_list` 传入调用 `va_arg` 的函数后处于不确定状态，不得再次使用。第二个回调若也调用 `vfprintf(fmt, ap)` 则会对已耗尽的 `va_list` 执行 `va_arg`，在 x86-64 上读取 `overflow_arg_area` 指针之外的栈内存，造成越界读。`tif_error.c` 中的 `TIFFError`/`TIFFErrorExt` 存在完全相同的缺陷（同文件 lines 50-72）。
- **触发条件**: 攻击者构造能在解析阶段触发 `TIFFWarning`/`TIFFWarningExt` 调用的畸形 TIFF 文件（如缺少必要 tag、不支持的 Photometric 值、IFD 字段值异常等），且宿主应用同时通过 `TIFFSetWarningHandlerExt()` 安装了非 NULL 的 `_TIFFwarningHandlerExt`（官方文档推荐用于多 TIFF 句柄的独立错误路由）。
- **安全影响**: 第二个回调中 `vfprintf` 对耗尽的 `va_list` 执行 `va_arg` 导致从栈帧之外的任意偏移量处越界读取，轻则进程崩溃（DoS），重则通过格式化输出将敏感栈内存内容（返回地址、指针、局部变量）泄露至日志/stderr，在部分架构/ABI 下可能引起 `overflow_arg_area` 悬空指针解引用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
