该文件为纯函数指针注册文件，逐行检查完毕：
- 无内存分配（无 malloc/av_malloc/memcpy）
- 无外部输入解析
- 数组索引均为硬编码常量（0–15），与 H264QpelContext 结构体定义一致
- `bit_depth` 由 codec 初始化路径传入，非容器字节流直接驱动

无可外部触发的内存安全漏洞。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
