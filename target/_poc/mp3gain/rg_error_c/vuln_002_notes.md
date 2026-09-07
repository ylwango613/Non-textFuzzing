# VULN 002 — ID3v2 Tag Size NULL Pointer Dereference

## Summary
mp3gain's `id3_parse_v2_tag()` reads a 4-byte syncsafe integer from the ID3v2 header
as the tag body length (`dlen`). It then calls `malloc(dlen)` without checking for NULL.
When `dlen` is set to its maximum syncsafe value (~268 MB), `malloc` may return NULL
under memory pressure, and the subsequent `fread(tagdata, 1, dlen, f)` with a NULL
`tagdata` pointer causes undefined behavior / SIGSEGV.

- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Location**: `id3tag.c` lines 545–546
- **Function**: `id3_parse_v2_tag()`

## Trigger Path
```
mp3gain main()
  -> ReadMP3GainID3Tag()
    -> id3_search_tag()
      -> id3_parse_v2_tag()   ← vulnerable
           tagdata = malloc(dlen);   // no NULL check
           fread(tagdata, 1, dlen, f); // crash if tagdata == NULL
```

## PoC Approach
`vuln_002_gen.py` constructs a minimal MP3 file:
- 10-byte ID3v2.3 header with size bytes `[0x7F, 0x7F, 0x7F, 0x7F]`
- Syncsafe integer decodes to 268,435,455 (≈256 MB) — triggers `malloc(268435455)`
- Followed by a minimal MP3 frame sync pattern

## Expected Behavior
| Scenario | Outcome |
|---|---|
| 32-bit system / low memory | `malloc` returns NULL → `fread(NULL,…)` → **SIGSEGV** |
| 64-bit with overcommit / ASAN | `malloc(268MB)` succeeds; `fread` returns short read; no crash (UNVERIFIED) |

## Limitations
On modern 64-bit Linux with overcommit enabled, `malloc(268435455)` typically succeeds
via virtual memory mapping and returns a valid (though uncommitted) pointer.
ASAN does not impose allocation limits by default.
In this case `fread` will read far fewer bytes than requested and return gracefully,
so the NULL dereference is not triggered and the vulnerability is **UNVERIFIED**.

To force the crash, run with a restricted virtual address space:
```bash
ulimit -v $((512 * 1024))  # limit to 512 MB virtual memory
bash vuln_002_run.sh
```
