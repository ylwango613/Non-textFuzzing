`AV_SAMPLE_FMT_DSD` 是 packed 格式（planar=0），所有通道数据均在 `frame->data[0]` 中。`size` 用 `int64_t` 计算无溢出，`ff_get_encode_buffer` 内部已做 `size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE` 的上界检查。`memcpy` 的目标和源大小均与 `size` 匹配。该文件 65 行，逻辑极简，无外部不可信字段直接控制内存操作，找不到可外部触发的内存安全漏洞。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
