`utils.hpp` 及其实现 `utils.cpp` 的完整内容如下：
- `contains()` — `constexpr`，仅调用 `std::string_view::find()`，无内存操作。
- `upper()` / `lower()` — 使用 `std::string::reserve()` + `push_back()`，已对 `char` 正确转型为 `unsigned char` 再传入 `std::toupper`/`std::tolower`，无裸指针、无索引运算、无外部输入驱动的大小计算。

三个函数均不涉及：缓冲区分配、偏移量计算、外部输入解析、递归、迭代器失效场景。无任何可外部触发的内存安全漏洞。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
