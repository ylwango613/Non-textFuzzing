文件完整读取完毕（1023 行）。现在对每个函数逐组分析：

**第 1 组（lines 1–942）：extern 声明 + codec_list 初始化**
- 全部为 `extern const FFCodec` 声明，无任何运行时操作
- `CONFIG_OSSFUZZ` 分支下 `codec_list[]` 为全 NULL 静态数组，无操作

**第 2 组（lines 944–954）：`av_codec_iterate()`**
```c
uintptr_t i = (uintptr_t)*opaque;
const FFCodec *c = codec_list[i];
```
- `codec_list` 是 NULL-terminated 静态数组，来自 `codec_list.c`
- `i` 来自调用方的 `opaque`；内部调用均以 `void *i = 0` 初始化并由本函数自增
- 若外部调用方传入超大 `i`，理论上可 OOB read；但该函数是公共 API，调用约定为从 0 开始——无法由媒体文件直接触发

**第 3 组（lines 956–963）：`remap_deprecated_codec_id()`**
- 仅 switch-return，无内存操作

**第 4 组（lines 965–984）：`find_codec()`**
- 仅迭代比较 `p->id == id` 和 `p->capabilities`，无内存分配/拷贝

**第 5 组（lines 996–1022）：`find_codec_by_name()`**
- `strcmp(name, p->name)` — 两侧均为 null-terminated C string，安全
- `!name` NULL 检查存在，无问题

**结论**：`allcodecs.c` 是纯粹的 codec 注册/查找模块，所有操作均基于静态编译时数据（`extern const` 全局变量、编译期固化的 `codec_list[]`）。文件中：
- 无任何 `av_malloc`/`av_realloc`/`memcpy` 调用
- 无任何来自外部媒体文件的字段（chunk_size、nb_entries、extradata_size 等）
- 无整数算术运算，无缓冲区操作
- 所有函数参数来自内部框架调用，不受攻击者控制的容器字节流直接驱动

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
