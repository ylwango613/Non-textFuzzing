# VULN-002: Stack Overflow via Unbounded Recursion in amf_data_yaml_dump

## Vulnerability Summary

- **Type**: CWE-674 Uncontrolled Recursion
- **Function**: `amf_data_yaml_dump()` in `dump_yaml.c:30-111`
- **Binary**: flvmeta (ASAN+UBSAN build)

## Root Cause

`amf_data_yaml_dump()` recursively calls itself for every element inside an AMF strict-array without any depth limit. When the nesting depth is large enough, the recursive call stack exceeds the OS stack limit (typically 8MB), causing a SIGSEGV stack-overflow crash.

## Trigger Path

```
flvmeta main()
  → dump_yaml_file()
    → flv_parse()
      → yaml_on_metadata_tag()
        → amf_data_yaml_dump(array_data)          [level 1]
          → amf_data_yaml_dump(nested_array)       [level 2]
            → ...                                  [level N]  ← stack overflow
```

## Stack Frame Budget

| Phase         | Frame size (approx) | Depth | Stack usage |
|---------------|---------------------|-------|-------------|
| Read (amf_data_read) | ~130 B/frame  | 35000 | ~4.5 MB — fits in 8 MB |
| YAML dump (amf_data_yaml_dump) | ~300 B/frame | 35000 | ~10.5 MB — overflows 8 MB |

The FLV is crafted so the read phase succeeds, but the subsequent YAML dump crashes.

## PoC File Structure

- **AMF payload**: `"onMetaData"` key followed by 35000 levels of `AMF0 strict-array (count=1)`, terminated by an `AMF0 number` leaf.
- Each strict-array level: `0x0A` (type) + `0x00000001` (count) = 5 bytes.
- Total payload: ~175 KB wrapped in a single FLV script tag.

## Reproduction

```bash
python3 vuln_002_gen.py
flvmeta vuln_002.flv   # triggers YAML dump → stack overflow
```

Expected crash: `AddressSanitizer: stack-overflow` or `Segmentation fault (SIGSEGV)`.
