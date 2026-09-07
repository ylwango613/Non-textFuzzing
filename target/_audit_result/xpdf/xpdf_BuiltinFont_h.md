After fully analyzing `BuiltinFont.h`, `BuiltinFont.cc`, `BuiltinFontTables.h`, and all callers:

- The hash table size (`size`) is always a compile-time constant > 0; `h % size` never divides by zero.
- `gmallocn` has its own overflow/zero guards.
- All call sites guard `enc[code]` for NULL before passing to `getWidth`.
- The `name` pointer used in `hash()` and `strcmp()` is always a valid null-terminated string from `copyString(obj3.getName())`.
- No attacker-controlled length is used for any allocation in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
