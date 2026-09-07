# VULN-001: Stack Overflow via Unbounded Recursion in AMF Parsing (flvmeta)

## Classification
- **CWE**: CWE-674 Uncontrolled Recursion
- **Type**: Stack overflow / SIGSEGV
- **Component**: libflvmeta AMF parser

## Trigger Path
```
flvmeta main()
  -> flv_parse()
     -> flv_read_metadata()
        -> amf_data_file_read()
           -> amf_data_read()         [reads type byte 0x0A -> array]
              -> amf_array_read()     [iterates count=1 elements, calls:]
                 -> amf_data_read()   [reads next type byte 0x0A -> array]
                    -> amf_array_read()
                       -> ... [70000 levels, no depth guard]
```

## Root Cause
`amf_data_read()` and `amf_array_read()` call each other recursively with no
depth limit. When parsing an AMF strict-array (type 0x0A), `amf_data_read`
calls `amf_array_read`, which iterates its element count and calls
`amf_data_read` for each element. A crafted payload with 70 000 levels of
single-element arrays exhausts the ~8 MB default thread stack.

## PoC Approach
`vuln_001_gen.py` constructs a minimal valid FLV file:

1. **FLV header** (9 bytes) + first previous_tag_size (4 bytes = 0).
2. **Script tag** (type 0x12) whose data is:
   - AMF string `"onMetaData"` (13 bytes): `0x02 0x00 0x0A o n M e t a D a t a`
   - 70 000 nested AMF strict-arrays (350 000 bytes):
     each level = `0x0A` (type) + `0x00 0x00 0x00 0x01` (count = 1)
   - Leaf AMF number 0.0 (9 bytes): `0x00` + 8 zero bytes
3. **Trailing previous_tag_size** (4 bytes).

Total FLV size: ~350 035 bytes.

## Reproduction
```bash
python3 vuln_001_gen.py          # produces vuln_001.flv
bash vuln_001_run.sh             # runs flvmeta, checks for crash
```

## Expected Outcome
The process crashes with **SIGSEGV** (exit code 139 / signal 11) due to
stack exhaustion. ASAN may additionally report a `stack-overflow` error.
No heap or buffer-overflow primitives are present; this is a pure
uncontrolled-recursion denial-of-service.

## Impact
Any user-supplied FLV file triggers a crash of the flvmeta process.
Severity is **medium** (DoS); no memory disclosure or code execution
primitive is observed.
