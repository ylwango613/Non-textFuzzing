After exhaustive analysis of `/data/ylwang/non-textfuzz/target/flvmeta/src/amf.c` and all related source files, I've traced every allocation and read in the parsing path:

**Parsing path allocations:**
- `amf_data_new()` — `malloc(sizeof(amf_data))`, fixed size, safe
- `amf_list_push()` — `malloc(sizeof(amf_node))`, fixed size, safe  
- `amf_string_read()` — `calloc(strsize, 1)` where `strsize` is `uint16` (max 65535), then `amf_string_new(buffer, strsize)` → `calloc(size+1, 1)` (max 65536), memcpy copies at most 65535 bytes into a 65536-byte buffer — safe
- `amf_array_read()` — loops on `uint32` count but exits on EOF, no preallocation

**API-level bugs found (not reachable from crafted FLV file):**
- `amf_object_delete()` lines 1014–1017: immediate `node = node->next` inside the while loop without NULL guard causes guaranteed NULL deref when iterating past the last node. **Not called from any `.c` file in the application** (confirmed by exhaustive grep across entire `src/`).
- `amf_list_insert_before()` lines 67–70 and `amf_list_insert_after()` lines 89–92: missing `node->prev = new_node` / `node->next = new_node` in the `else` branch, corrupting the doubly-linked list. **Not called from any `.c` file in the application.**

**Direct file-triggered memory corruption:** None found. The parsing functions (`amf_string_read`, `amf_object_read`, `amf_associative_array_read`, `amf_array_read`, `amf_date_read`) correctly bound all reads to `uint16`-limited sizes, handle EOF through `fread` natural limits, and only use `amf_list_push()` which is safe. The `copy_buffer` in `update.c` is bounded by the 24-bit FLV tag body length field (max 16 MB), preventing integer overflow. The `amf_data_size()` size_t result is cast to `uint32` in callers but never subsequently used as a `malloc` argument.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
