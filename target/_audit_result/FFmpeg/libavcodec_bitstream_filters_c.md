The file is only 127 lines — a pure static registry. All three functions (`av_bsf_iterate`, `av_bsf_get_by_name`, `ff_bsf_child_class_iterate`) operate exclusively on compile-time constant arrays and structures, do no memory allocation, perform no buffer copies, and process no data from external media files. The included `bsf_list.c` (build-generated, not present) is a static pointer array. There is no path from attacker-controlled input to any operation in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
