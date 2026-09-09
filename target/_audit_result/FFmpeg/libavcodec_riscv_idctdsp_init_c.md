The file `idctdsp_init.c` is 49 lines and contains only a single function `ff_idctdsp_init_riscv()` that checks CPU flags and conditionally assigns three function pointers. The associated assembly file `idctdsp_rvv.S` implements those three functions operating on fixed-size 8×8 blocks (64 elements, hardcoded).

There are no memory allocations, no `memcpy`/`memset`, no array indexing with user-controlled indices, no integer arithmetic, and no processing of any external input in either file. The function pointer targets operate on caller-provided pointers with fixed-size access patterns defined by the IDCT block convention (int16_t[64] input, uint8_t destination, stride). No user-controlled size or count field is involved at any point in this code path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
