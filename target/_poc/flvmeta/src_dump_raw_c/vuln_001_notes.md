# VULN 001 - Uncontrolled Recursion in amf_data_read (flvmeta)

## Vulnerability Summary
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **Functions**: amf_data_read() / amf_object_read() / amf_array_read()
- **Binary**: flvmeta

## Trigger Path
```
flvmeta main()
  -> dump_raw_file()
    -> flv_parse()
      -> flv_read_metadata()
        -> amf_data_file_read()
          -> amf_data_read()          # reads type byte 0x03 (AMF object)
            -> amf_object_read()      # reads key-value pairs
              -> amf_data_read()      # reads value (another 0x03 object)
                -> amf_object_read()  # recurses again ...
                  -> ... (unbounded until stack exhausted)
```

## PoC Approach
`vuln_001_gen.py` constructs a binary FLV file with a Script tag whose AMF payload
contains 5000 levels of nested AMF objects (type byte `0x03`). Each nesting level
consists of a single key "a" whose value is the next AMF object. The innermost value
is an AMF number (`0x00` + 8-byte double).

Because `amf_data_read` and `amf_object_read` call each other recursively with no
depth guard, 5000 levels of nesting (each consuming ~hundreds of bytes of stack frame)
exhausts the default 8 MB stack, causing a stack overflow (SIGSEGV / signal 11).

## Expected Behaviour
- flvmeta crashes with SIGSEGV (stack overflow)
- ASAN (if instrumented) reports "stack-overflow" or "SEGV on unknown address"
- Exit code is non-zero (139 for SIGSEGV)

## Files
| File | Purpose |
|------|---------|
| vuln_001_gen.py | Generates the malicious FLV file iteratively |
| vuln_001_run.sh | Runs flvmeta and captures output/ASAN logs |
| vuln_001.flv    | Crafted FLV file (generated at runtime) |
| vuln_001_result.txt | Captured crash output |
