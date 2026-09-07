# VULN 002 – NULL Pointer Dereference via Unchecked g_try_malloc in GDI+ Property Access Functions

## Vulnerability Summary

| Field | Detail |
|---|---|
| CWE | CWE-476 – NULL Pointer Dereference |
| File | `gdk-pixbuf/io-gdip-utils.c` lines 494, 524, 411 |
| Functions | `gdip_bitmap_get_frame_delay`, `gdip_bitmap_get_n_loops`, `gdip_bitmap_get_property_as_string` |
| Attack vector | Crafted animated GIF / image file processed under memory pressure |

## Root Cause

Each of the three affected functions follows the same pattern:

```c
item_size = ...;
item = g_try_malloc(item_size);          // line ~494 / 524 / 411
GdipGetPropertyItem(bitmap, tag, item_size, item);  // item may be NULL
```

`g_try_malloc` is the non-aborting allocator: it returns `NULL` on allocation failure
instead of calling `g_error`. The return value is **not checked** before `item` is
passed to `GdipGetPropertyItem`. When memory is exhausted, `item` is `NULL` and
`GdipGetPropertyItem` writes into address 0, producing a NULL pointer dereference.

The call chain that reaches these functions is:

```
gdk_pixbuf__gdip_image_stop_load
  └─ stop_load  (io-gdip-animation.c)
       ├─ gdip_bitmap_get_frame_delay       (io-gdip-utils.c:494)
       ├─ gdip_bitmap_get_n_loops           (io-gdip-utils.c:524)
       └─ gdip_bitmap_get_property_as_string (io-gdip-utils.c:411)
```

## Why This Vulnerability Cannot Be Triggered Here

### Blocker 1 – No GDI+ / GIF Loader in This Linux Build

GDI+ (`libgdiplus` / the Windows GDI+ API) is a **Windows-only** subsystem. The
loader files `io-gdip-animation.c` and `io-gdip-utils.c` are compiled and linked only
on Windows builds of gdk-pixbuf.

The test binary at:
```
/data/ylwang/non-textfuzz/target/gdk-pixbuf/build_test/bin/gdk-pixbuf-pixdata
```
was built on Linux and contains **only** the `pixdata` format loader
(`_gdk_pixbuf__pixdata_fill_vtable`). No GIF loader and no GDI+ loader are present.
When the binary is given any GIF file it immediately returns:

> "Couldn't recognize the image file format for file '...'"

The vulnerable code paths are therefore unreachable on this system.

### Blocker 2 – Requires OOM Conditions (g_try_malloc returns NULL)

Even on a system where the GDI+ loader is available, the vulnerability is conditional
on `g_try_malloc` returning `NULL`. This happens only when the process cannot satisfy
the allocation – an Out-of-Memory (OOM) condition.

A crafted file alone cannot reliably force this:
- The allocation sizes involved (`item_size` derived from image property metadata) are
  typically small (tens to hundreds of bytes).
- Modern operating systems over-commit memory; `g_try_malloc` almost never returns
  `NULL` unless the system is genuinely under extreme memory pressure.
- Reproducing the bug reliably requires either: (a) running inside a container or
  cgroup with a very tight memory limit, or (b) using `ulimit -v` / `LD_PRELOAD`
  malloc-failure injection to simulate OOM at the right moment.

## Environment Required to Trigger the Vulnerability

1. **Windows** with `libgdiplus` or the native Windows GDI+ runtime, running a
   Windows build of gdk-pixbuf that includes `io-gdip-animation.c`.
   -or-
   A cross-compiled Linux build with `libgdiplus` (`mono-libgdiplus`) and the
   `gdip` loader enabled in the build system.

2. A mechanism to induce OOM at the moment `g_try_malloc` is called:
   - Tight cgroup/container memory limit (e.g., `--memory=16m` in Docker).
   - `ulimit -v <small_value>` before invoking the process.
   - A custom `LD_PRELOAD` shim that causes `malloc` to return `NULL` after N calls.

3. A crafted animated GIF with NETSCAPE 2.0 loop extension and per-frame delay
   properties (to ensure all three vulnerable property-fetch paths are exercised).

## Attack Scenario

An attacker supplies a crafted animated GIF to an application that uses the GDI+
gdk-pixbuf loader (e.g., a Windows GTK application). If the system is under memory
pressure at the time the image is loaded, `g_try_malloc` returns `NULL` inside one
of the property-access functions, and `GdipGetPropertyItem` writes to address zero,
crashing the process (Denial of Service) or – on systems without memory protections –
potentially enabling code execution via controlled NULL page mapping.

## PoC Files

| File | Purpose |
|---|---|
| `vuln_002_gen.py` | Generates `vuln_002.gif`: a 20-frame animated GIF89a with NETSCAPE loop extension and per-frame delay values, designed to exercise the property access code paths |
| `vuln_002_run.sh` | Runs the generator then invokes `gdk-pixbuf-pixdata` with ASAN logging |
| `vuln_002_result.txt` | Captured output (expected: format not recognised) |
| `vuln_002_status.txt` | Status: SKIPPED (two blockers above) |
