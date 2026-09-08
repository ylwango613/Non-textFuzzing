All `dot_productf` call sites pass compile-time constants (`AMRWB_SFR_SIZE`, `AMR_SUBFRAME_SIZE`, `UPS_MEM_SIZE`, `AMR_TILT_RESPONSE`) — none are derived from the input bitstream. The arrays themselves are internally allocated to exactly those fixed sizes. The file contains no memory allocation, no bitstream-controlled sizes, and no integer arithmetic feeding into buffer operations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
