Complete analysis of `threadprogress.c` (79 lines):

- **No dynamic memory allocation** — no `av_malloc`, `av_realloc`, `malloc`, `memcpy`, or any heap operations.
- **No buffer access with user-controlled indices** — the only data manipulated are atomic integers and compile-time offset arrays.
- **`ff_thread_progress_init`** initializes an atomic int and optionally a mutex/condvar via `ff_pthread_init`. All values are compile-time constants or a boolean `init_mode` (used only as 0/-1/INT_MAX).
- **`ff_thread_progress_report` / `ff_thread_progress_await`** only perform mutex lock/unlock, condvar wait/broadcast, and atomic store/load on an `int`. No size arithmetic, no buffers.
- **The `const`-cast at line 69** is safe: the function only reads `progress` and leaves the struct state identical on return; no write through a logically-const pointer reachable from outside.
- **`DEFINE_OFFSET_ARRAY`** macro produces a static array of compile-time `offsetof` values — no user-controlled data.

None of the audited patterns (integer overflow → underalloc, OOB write, heap/stack overflow, unvalidated external size fields) are present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
