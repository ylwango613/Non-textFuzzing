All buffer_length values passed to the MIPS function pointer are compile-time constants: AMR_SUBFRAME_SIZE=40, AMRWB_SFR_SIZE=64, AMRWB_SFR_SIZE_16k=80 — all multiples of 8. All filter_length values (LP_FILTER_ORDER=10, LP_ORDER=16, LP_ORDER_16k=20) are even and >4, satisfying documented preconditions. The asm boundary calculations are correct for these inputs. No externally-triggerable memory safety defect exists in this MIPS-only file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
