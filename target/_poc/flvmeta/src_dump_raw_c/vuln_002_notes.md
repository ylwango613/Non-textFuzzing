# VULN 002: Uncontrolled Recursion in amf_data_dump (CWE-674)

## Summary

`amf_data_dump()` in `amf.c` (lines 788-856) recurses unconditionally for
every nested AMF container it encounters.  Each recursive call allocates a
128-byte `char datestr[128]` local buffer on the stack, making each frame
larger than the parse-phase frames used in VULN 001.

~4,000 levels of nesting is sufficient to exhaust the default Linux stack
(8 MB) and trigger a SIGSEGV / `AddressSanitizer: stack-overflow`.

## Trigger Path

```
flvmeta main()
  -> dump_raw_file()          (dump_raw.c)
     -> flv_parse()
        -> raw_on_metadata_tag()   (dump_raw.c:124)
           -> amf_data_dump(stdout, data, 0)
              -> amf_data_dump(..., indent_level+1)   [for nested container]
                 -> amf_data_dump(..., indent_level+2)
                    -> ...  (unbounded recursion)
```

## Key Difference from VULN 001

| Aspect          | VULN 001 (parse phase)  | VULN 002 (dump phase)   |
|-----------------|-------------------------|-------------------------|
| Crashing fn     | amf_data_from_file()    | amf_data_dump()         |
| Frame size      | smaller                 | +128 bytes (datestr)    |
| Depth needed    | ~8000                   | ~4000                   |
| FLV AMF type    | strict array (0x0A)     | ecma_array (0x08)       |
| Trigger command | `flvmeta file.flv`      | `flvmeta file.flv`      |

## Reproduction

```bash
python3 vuln_002_gen.py          # create vuln_002.flv
bash vuln_002_run.sh             # run flvmeta and capture output
cat vuln_002_result.txt          # check for crash indicators
```

## Expected Output

```
AddressSanitizer: stack-overflow on address 0x...
```

or a non-zero exit with a SIGSEGV signal indicator.
