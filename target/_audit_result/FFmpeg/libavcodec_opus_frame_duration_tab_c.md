The file `frame_duration_tab.c` is a pure static data table defining 32 constant `uint16_t` values. The single access site in `parse.c:250` derives the index as `(byte >> 3) & 0x1F`, which is a 5-bit mask giving values 0–31 — exactly matching the array bounds. There is no logic, allocation, or parsing in this file, and the index is unconditionally bounded before use.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
