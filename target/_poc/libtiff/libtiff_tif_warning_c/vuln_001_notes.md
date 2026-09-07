# VULN-001: Double va_list Use After Consumption in TIFFWarning / TIFFWarningExt

## Status: SKIPPED

## Reason

The vulnerability requires a non-NULL `_TIFFwarningHandlerExt` to be installed by the host application via `TIFFSetWarningHandlerExt()`. The bug is only reachable when **both** conditions are true:

1. A warning is emitted during TIFF parsing (triggering `TIFFWarning()` or `TIFFWarningExt()`).
2. The application has installed a non-NULL ext handler via `TIFFSetWarningHandlerExt()`.

### Evidence from source

**libtiff/tif_warning.c** (the vulnerable code):
```c
// Line 32: global default is NULL
TIFFErrorHandlerExt _TIFFwarningHandlerExt = NULL;

// Lines 50-60: TIFFWarning()
void TIFFWarning(const char* module, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (_TIFFwarningHandler)
        (*_TIFFwarningHandler)(module, fmt, ap);   // consumes ap
    if (_TIFFwarningHandlerExt)
        (*_TIFFwarningHandlerExt)(0, module, fmt, ap); // ap is exhausted here — BUG
    va_end(ap);
}
```

The second handler call at line 58 passes an already-consumed `va_list ap` to the ext handler, which then calls `vfprintf(fmt, ap)` on exhausted stack state — leading to out-of-bounds reads (CWE-125). However, the guard `if (_TIFFwarningHandlerExt)` means this path is only taken when a non-NULL ext handler has been installed.

**tools/tiffsplit.c** (the target binary):
- The entire `tiffsplit.c` source (297 lines) contains **no call** to `TIFFSetWarningHandlerExt()`.
- `tiffsplit` never installs a non-NULL `_TIFFwarningHandlerExt`.
- Therefore, `_TIFFwarningHandlerExt` remains NULL throughout the entire `tiffsplit` execution.
- The `if (_TIFFwarningHandlerExt)` guard at line 57/69 of tif_warning.c is never satisfied.
- The vulnerable second `vfprintf` call is **never reached**.

## What Would Be Required to Trigger

To trigger this bug, the vulnerable application would need to:
```c
TIFFSetWarningHandlerExt(some_handler_that_calls_vfprintf_with_fmt_and_ap);
```

This is a library-level vulnerability that affects applications using libtiff which have registered a custom ext warning handler (e.g., custom logging frameworks, GUI applications, servers). It is **not exploitable via the tiffsplit command-line tool** without source modification.

## Trigger Path (Why It Fails Here)

```
tiffsplit main()
  -> TIFFOpen(argv[1], "r")
    -> TIFFReadDirectory()
      -> TIFFWarning() / TIFFWarningExt()
        -> _TIFFwarningHandler called (default stderr handler) — ap consumed
        -> if (_TIFFwarningHandlerExt)  <-- FALSE, handler is NULL
           [second handler never called]
        -> va_end(ap)
```

## Files Generated

- `vuln_001_status.txt`: SKIPPED
- `vuln_001_notes.md`: this file
- No `vuln_001_gen.py` or `vuln_001_run.sh` generated (per SKIP rules)
