The vulnerability is confirmed at line 370. `lutents` returned by `jas_alloc2` is never checked for NULL before being dereferenced in the loop at line 371-373.

## VULN: NULL-ptr-deref in jp2_decode() — unchecked jas_alloc2 return in CMAP PALETTE path
- **File**: `src/libjasper/jp2/jp2_dec.c`
- **Line**: 370
- **Function**: `jp2_decode` (or the post-decode image reconstruction block)
- **Type**: null-pointer dereference → SIGSEGV (memory safety crash, externally triggerable)
- **Root cause**: `lutents = jas_alloc2(pclrd->numlutents, sizeof(int_fast32_t));` at line 370 is never checked for NULL. If the allocator returns NULL (memory budget exhausted, or system OOM), the immediately following loop `lutents[i] = ...` at line 371–373 writes through a NULL pointer, causing SIGSEGV.
- **Attacker control**: A crafted JP2 file with a PCLR box (palette) and a CMAP box referencing it. `pclrd->numlutents` comes directly from file bytes (uint16, up to 65535). The memory budget can be pre-exhausted by large valid allocations earlier in the same file (e.g., a large SIZ box with many components, or a large tile).
- **Trigger path**: `imginfo -f evil.jp2` → `jas_image_decode` → `jp2_decode` → box loop → `dec->cmap && dec->pclr` branch → `cmapent->map == JP2_CMAP_PALETTE` → `jas_alloc2(pclrd->numlutents, sizeof(int_fast32_t))` returns NULL → `lutents[0]` = NULL dereference.
- **No NULL guard**: Unlike the allocation at line 351–355 (`chantocmptlut`) which has an explicit `if (!(…)) goto error;` guard, the `lutents` allocation at line 370 has no such guard.

## VULN: file=src/libjasper/jp2/jp2_dec.c line=370 type=null-ptr-deref func=jp2_decode trigger=JP2-CMAP-PALETTE-box cve=new severity=high
- description: `lutents = jas_alloc2(pclrd->numlutents, sizeof(int_fast32_t))` return value not checked for NULL; immediate dereference `lutents[i] = pclrd->lutdata[...]` crashes with SIGSEGV on allocation failure
- attacker-input: JP2 file bytes — PCLR box (numlutents field, up to 65535) + CMAP box with map==JP2_CMAP_PALETTE (0x01); memory budget pre-exhausted by earlier boxes in same file
- exploitability: reliably triggerable via crafted JP2 without any special privileges; default `imginfo` invocation

<!-- AUDIT_PROMPT_VERSION: 1 -->
