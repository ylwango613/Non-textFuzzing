# vuln_002: SENC Atom Integer Underflow → ~4 GB Allocation → Crash

## CWE
CWE-191: Integer Underflow (Wrap or Wraparound)

## Root Cause

In `AP4_SencAtom::Create()` (Ap4CommonEncryption.cpp), the size check is:

```cpp
if (size < 12) return NULL;
```

This only rejects boxes smaller than 12 bytes. A box with `size == 12` passes through.

## Trigger Condition

Inside the `AP4_SencAtom` constructor, payload size is computed as:

```cpp
payload_size = size - header_size - 4;
// header_size = 12 (size + type + version + flags)
// so: payload_size = 12 - 12 - 4 = 12 - 16
```

Because `payload_size` is an **unsigned** integer:
- `12 - 16 = -4` wraps to `0xFFFFFFFC` ≈ 4,294,967,292 bytes ≈ **4.29 GB**

## Exploit Chain

1. Craft a `senc` box that is exactly 12 bytes: `\x00\x00\x00\x0c` + `senc` + `\x00\x00\x00\x00`
2. Place it inside `moof → traf`
3. Parser calls `AP4_SencAtom::Create()` with size=12 → passes the check
4. Constructor computes `payload_size = 0xFFFFFFFC`
5. `m_SampleInfos.SetDataSize(0xFFFFFFFC)` → tries to allocate ~4 GB
6. `std::bad_alloc` → process crash (DoS)

## Expected Output

- `terminate called after throwing an instance of 'std::bad_alloc'`
- `what(): std::bad_alloc`
- ASAN may report `allocation-size-too-big` or similar
- Process exits with non-zero status

## Impact

Denial of Service: any attacker-supplied MP4 file with a 12-byte `senc` atom
causes the Bento4 mp42aac process to crash due to an attempted ~4 GB allocation.
