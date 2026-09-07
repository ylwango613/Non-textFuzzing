# VULN 001 — yaml_string_write_handler Heap Buffer Overflow

## Status: SKIPPED

## 跳过原因

该漏洞存在于 `yaml_string_write_handler()`（api.c:418-432），触发条件是调用方通过 `yaml_emitter_set_output_string()` 设置固定大小字符串输出缓冲区后累积写入超过缓冲区容量。

然而，经过对 flvmeta 源码的确认：

- `dump_yaml.c:460` 和 `dump_yaml.c:485` 均只调用 `yaml_emitter_set_output_file(&emitter, stdout)`
- flvmeta 从未调用 `yaml_emitter_set_output_string()`

因此 `yaml_string_write_handler` 在 flvmeta 的任何实际执行路径中都不会被调用——libyaml 根据 emitter 类型分发到不同的 write handler（文件模式走 `yaml_file_write_handler`，字符串模式才走 `yaml_string_write_handler`）。

无论构造何种 FLV 文件，通过命令行传入 flvmeta 二进制均无法到达该代码路径，必须修改源码才能触发。依据跳过规则，本漏洞标记为 SKIPPED。
