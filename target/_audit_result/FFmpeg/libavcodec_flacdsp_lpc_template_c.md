The picture is now complete. With `FLAC_MAX_BLOCKSIZE = 65535`:

- `samples[FLAC_MAX_BLOCKSIZE]` → indices 0..65534
- `residual[FLAC_MAX_BLOCKSIZE+11]` → indices 0..65545

The loop in both code paths (`lpc_encode_unrolled` and the `CONFIG_SMALL` branch) accesses `smp[i+1]` and `res[i+1]` where `i` can reach `len-1` when `(len - order)` is odd. For `len = blocksize`:

- `res[blocksize] = residual[blocksize]`: always within `residual[FLAC_MAX_BLOCKSIZE+11]` ✓ — the `+11` extension intentionally absorbs the one-past-end write.
- `smp[blocksize] = samples[blocksize]`: when `blocksize < FLAC_MAX_BLOCKSIZE` → within `samples[65535]` ✓; when `blocksize = FLAC_MAX_BLOCKSIZE = 65535` → technically past `samples[]` but lands on `residual[0]` (next contiguous struct field), which is valid allocated memory.

The `+11` over-allocation on `residual` is a deliberate design choice to accommodate the two-samples-per-iteration LPC unrolling, and the struct field ordering (`samples` immediately followed by `residual`) ensures the edge-case `smp[FLAC_MAX_BLOCKSIZE]` read also remains within the struct. Neither access escapes the `FlacSubframe` object. Additionally, this is encoder-only code — it processes PCM samples already decoded from the input, not raw container bytes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
