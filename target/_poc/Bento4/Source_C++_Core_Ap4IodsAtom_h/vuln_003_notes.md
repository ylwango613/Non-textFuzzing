# VULN 003 - AP4_EsDescriptor SubStream Integer Underflow

## Summary

**Vulnerability**: Integer underflow in `AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)`  
**File**: `Bento4/Source/C++/Core/Ap4EsDescriptor.cpp`, lines 100-103  
**Trigger**: `payload_size(2u) - AP4_Size(offset-start)(3u) = 0xFFFFFFFF`

## Root Cause Analysis

In `Ap4EsDescriptor.cpp`:

```cpp
AP4_Position start;
stream.Tell(start);                        // line 67: record start

stream.ReadUI16(m_EsId);                   // line 70: consumes 2 bytes
unsigned char bits;
stream.ReadUI08(bits);                     // line 72: consumes 1 byte
// ... conditional reads based on flags (none in our case) ...

AP4_Position offset;
stream.Tell(offset);                       // line 100: offset = start + 3

AP4_SubStream* substream = new AP4_SubStream(stream, offset,
    payload_size-AP4_Size(offset-start));  // line 102-103: 2u - 3u = 0xFFFFFFFF!
```

When `payload_size=2` and the constructor has consumed 3 bytes:
- `offset - start = 3`
- `AP4_Size(offset-start) = 3` (as uint32)
- `payload_size - 3 = 2u - 3u` → **unsigned underflow** → `0xFFFFFFFF`
- A SubStream of ~4.3 GB is created

## Trigger Path

```
mp42aac
 -> AP4_File
   -> AP4_MoovAtom
     -> AP4_IodsAtom (via AP4_AtomFactory)
       -> AP4_DescriptorFactory::CreateDescriptorFromStream
         -> AP4_InitialObjectDescriptor (tag=0x10, payload_size=12)
            * ReadUI16: 2B bits (OD_ID, url_flag, inline flags)
            * ReadUI08 x5: 5B profile levels
            * Creates IOD SubStream (size = 12-7 = 5 bytes)
              IOD SubStream content: [0x03][0x02][0x00][0x01][0x00]
           -> AP4_DescriptorFactory on IOD SubStream
             -> AP4_EsDescriptor (tag=0x03, payload_size=2)
                stream pos=2 when constructor called
                * ReadUI16(ES_ID): 2 bytes, pos: 2->4
                * ReadUI08(flags): 1 byte (extra byte!), pos: 4->5
                * offset-start = 5-2 = 3
                * 2u - 3u = 0xFFFFFFFF  ← UNDERFLOW HERE
                * AP4_SubStream(iod_substream, 5, 0xFFFFFFFF)
```

## MP4 File Structure

```
ftyp [20B]: mp42
moov [142B]:
  mvhd [108B]: version=0, timescale=1000
  iods [26B]:
    version=0, flags=0
    IOD descriptor (tag=0x10, size=0x0C=12):
      2B: 0x00 0x0F  (OD_ID=0, url=0, inline=0, reserved=0xF)
      5B: 0xFF x5    (profile levels: OD/Scene/Audio/Visual/Graphics)
      4B: 0x03 0x02 0x00 0x01  (ES tag, size=2, ES_ID=1)
      1B: 0x00       ← CRITICAL: extra byte, read as ES flags by constructor
                       Enables all 3 bytes to be consumed -> underflow condition
```

Hex of iods payload area:
```
10 0c  00 0f  ff ff ff ff ff  03 02 00 01  00
^^IOD  ^^bits  ^^^profiles^^^^  ^^^ES_Desc^  ^^extra
```

## Why the Extra Byte is Critical

Without the extra byte at position 4 in the IOD SubStream:
- `ReadUI08(bits)` hits EOS at position 4 (= IOD SubStream size), position stays at 4
- `offset - start = 4 - 2 = 2`
- `payload_size - 2 = 2 - 2 = 0` → NO underflow

With the extra byte:
- `ReadUI08(bits)` succeeds, reading 0x00 as flags, position advances to 5
- `offset - start = 5 - 2 = 3`
- `payload_size - 3 = 2 - 3 = 0xFFFFFFFF` → **UNDERFLOW**

## Sanitizer Analysis

**Build flags**: `-fsanitize=address,undefined -g0 -fno-omit-frame-pointer`

**Why ASAN does not fire**:
- `AP4_SubStream` object is small; the huge `m_Size=0xFFFFFFFF` is just a field value
- No buffer of 4.3 GB is allocated
- All reads through the oversized SubStream go through the IOD SubStream which properly returns EOS (no out-of-bounds memory access)

**Why UBSAN does not fire**:
- The subtraction `AP4_Size(2) - AP4_Size(3)` involves `AP4_Size = uint32_t` (unsigned)
- `-fsanitize=undefined` includes `signed-integer-overflow` but NOT `unsigned-integer-overflow`
- Unsigned integer overflow/underflow requires explicit `-fsanitize=unsigned-integer-overflow` or `-fsanitize=integer`

**To detect with UBSAN**: Recompile with `-fsanitize=address,undefined,unsigned-integer-overflow`

## Impact Assessment

The underflow creates an oversized SubStream (0xFFFFFFFF) that:
1. In this PoC: the IOD SubStream is exhausted; EOS is returned immediately; no further effect
2. In a deeper crafted file (with more data in IOD payload beyond position 5): the ES SubStream would read and parse arbitrary bytes as ES sub-descriptors, potentially triggering further bugs in `AP4_DecoderConfigDescriptor`, `AP4_DecoderSpecificInfoDescriptor`, etc.

## Files

| File | Description |
|------|-------------|
| `vuln_003_gen.py` | Generates `vuln_003.mp4` (162 bytes) |
| `vuln_003_run.sh` | Runs mp42aac and collects output |
| `vuln_003.mp4` | Crafted MP4 triggering the underflow |
| `vuln_003_result.txt` | Binary execution output |
| `vuln_003_notes.md` | This file |
| `vuln_003_status.txt` | Verification status |
