# VULN 001 — Uncontrolled Recursion via Nested AMF Objects in flvmeta

## CWE
CWE-674: Uncontrolled Recursion

## Vulnerability Summary
flvmeta contains mutually recursive parsing functions `amf_data_read()` and
`amf_object_read()` and a self-recursive dump function `json_amf_data_dump()`.
None of these functions impose a maximum recursion depth. A crafted FLV file
carrying a Script tag with deeply nested AMF objects will cause the process
stack to overflow, producing a SIGSEGV crash.

## Trigger Path
```
flvmeta input.flv
  → dump_json_file()
    → amf_data_read()           # reads type byte 0x03 → AMF_TYPE_OBJECT
      → amf_object_read()       # reads key-value pairs; value calls amf_data_read()
        → amf_data_read()       # next nesting level
          → amf_object_read()   # ... repeats ~50,000 times
  → json_amf_data_dump()        # recursive dump mirrors the same depth
```

## PoC Construction
- `vuln_001_gen.py` builds 50,000 nested AMF objects from the inside out:
  - Innermost value: AMF number (type `0x00` + 8 zero bytes)
  - Each wrapper layer: `0x03` (object) + key `"a"` (2-byte length + byte) + inner + `0x00 0x00 0x09` (end marker)
- The payload is placed as the value of `"onMetaData"` in a Script tag so
  `flvmeta` parses it during its default metadata display operation.

## Expected Result
- SIGSEGV / "Segmentation fault" due to stack exhaustion
- The crash occurs during recursive AMF parsing, before or during JSON dump
- ASAN stack-buffer-overflow may also fire if the binary was built with ASAN

## Files
| File | Purpose |
|------|---------|
| `vuln_001_gen.py` | Generates `vuln_001.flv` (the malicious input) |
| `vuln_001_run.sh` | Runs flvmeta and captures crash output |
| `vuln_001_result.txt` | Raw crash output from flvmeta |
| `vuln_001_status.txt` | Single-line verification verdict |
