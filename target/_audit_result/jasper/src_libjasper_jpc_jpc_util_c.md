Complete analysis findings:

**`jpc_atoaf` (lines 91–137):** Only call site is `jpc_enc.c:547` (encoder option parsing, not the decoder). Input `s` originates from the `jas_tvparser` option string, not from image file bytes. `strncpy` is bounded to `sizeof(buf)=4096` with explicit NUL termination; `jas_alloc2` carries built-in overflow checking. Not reachable from `imginfo -f`.

**`jpc_seq_upsample` (lines 139–152):** Defined here and declared in `jpc_util.h`, but grep across the entire source tree finds zero call sites. Dead code — never invoked.

**`jpc_seq_norm` (lines 154–165):** Same — zero call sites in the whole tree. Dead code.

**`jpc_seq_conv` (lines 167–194):** Same — zero call sites. Dead code. (The `assert(z)` would abort on OOM, but it is unreachable.)

None of the four functions in `jpc_util.c` are reachable via the `imginfo -f <file>` attack surface.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
