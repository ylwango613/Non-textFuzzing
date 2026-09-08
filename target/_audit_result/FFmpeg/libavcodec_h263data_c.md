The file `h263data.c` contains exclusively compile-time constant lookup tables — no functions, no dynamic memory allocation, no parsing of external data, and no index arithmetic on untrusted inputs. The `ff_h263_format[8][2]` array has only 6 explicit initializers (remaining two entries are zero-initialized per C standard), and all call sites (`intelh263dec.c:72`, `ituh263dec.c:1143`, `mpegvideo_enc.c:878`) correctly guard against out-of-bounds access before indexing. There are no memory safety vulnerabilities in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
