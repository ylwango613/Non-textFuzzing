# VULN 001 - PoC Status: SKIPPED

## Vulnerability Summary

**Function:** `dirac_combine_frame()` in `libavcodec/dirac_parser.c`, lines 190–231  
**Root cause:** Signed integer overflow in `pc->dirac_unit_size` (type `int`) at line 205:
```c
pc->dirac_unit_size += pu.next_pu_offset;
```

## Why a Practical PoC File Is Infeasible

### The gating check at line 190

Every time `dirac_combine_frame()` accumulates into `dirac_unit_size`, it first evaluates:

```c
if (!unpack_parse_unit(&pu1, pc, pc->index - 13)                     ||
    !unpack_parse_unit(&pu, pc, pc->index - 13 - pu1.prev_pu_offset) ||
    pu.next_pu_offset != pu1.prev_pu_offset                          ||
    pc->index < pc->dirac_unit_size + 13LL + pu1.prev_pu_offset      // <-- gating check
) {
    pc->index              -= 9;
    *buf_size               = next - 9;
    pc->header_bytes_needed = 9;
    return -1;   // returns WITHOUT accumulating
}
```

The gating check `pc->index < pc->dirac_unit_size + 13LL + pu1.prev_pu_offset` uses `13LL`
to force 64-bit arithmetic. The check ensures that the internal buffer (`pc->buffer`) actually
contains at least `dirac_unit_size + pu1.prev_pu_offset + 13` bytes before any new
`next_pu_offset` is added. If the buffer is short, the function returns -1 and accumulation
does not occur.

`pc->index` tracks the number of bytes physically present in `pc->buffer`; it only grows as
the parser receives real input data. There is no speculative or lazy path that advances
`dirac_unit_size` without the corresponding bytes being present.

### Math for the overflow

For `dirac_unit_size` (signed 32-bit `int`) to overflow:

    sum of all accumulated next_pu_offset values > INT_MAX = 2,147,483,647

Each `next_pu_offset` must be ≥ 13 (enforced by `unpack_parse_unit`). Even at the minimum
value of 13 bytes per unit:

    ceil(2,147,483,647 / 13) ≈ 165,191,050 parse units
    165,191,050 × 13 bytes   ≈ 2.1 GB of file data

If using fewer, larger units (e.g., two units with `next_pu_offset = 0x40000001`):

    2 × 0x40000001 = 0x80000002 bytes ≈ 2.0 GB of file data

### No workaround exists

- **Chunk-by-chunk processing:** The parser does process input in chunks, but the internal
  buffer accumulates ALL received bytes. The overflow check is evaluated against
  `pc->index` (bytes in the accumulated buffer), not against an external file size.
  The parser cannot process a header whose preceding payload is absent.

- **Using zero-payload units:** `next_pu_offset = 0` only passes validation for
  `EndOfSequence` (pu_type 0x10) and is special-cased to `next_pu_offset = 13`, contributing
  no more than 13 per unit.

- **Chain length:** Any chain of N units with minimum size 13 still requires ≥ 2 GB total.

### Conclusion

Triggering this vulnerability requires creating (and feeding to ffmpeg) a file containing
over 2 GB of syntactically valid Dirac parse-unit payload data. This is impractical as a
standalone PoC artifact. The vulnerability is real but requires either:

1. A fuzzing campaign on a system with large memory that generates 2+ GB inputs, or  
2. A kernel-level trick (e.g., /proc/self/mem or a FUSE filesystem that synthesizes large
   zero-filled blocks on demand) rather than a static crafted file.

Because the task rules permit only a static Python-generated binary file, the PoC is marked
**SKIPPED**.
