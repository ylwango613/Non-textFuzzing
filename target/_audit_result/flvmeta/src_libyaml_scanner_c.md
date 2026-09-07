Confirmed: flvmeta uses only `yaml_emitter_*` for YAML output — never `yaml_parser_*` for input. The scanner.c code (YAML tokenizer/parser) is compiled into the binary from the bundled libyaml but **none of flvmeta's own source files ever call yaml_parser_initialize(), yaml_parser_set_input*(), or any scanner function**. No user-controlled data — FLV file bytes or otherwise — is fed into the YAML scanner path. The `yaml_parser_scan_uri_escapes` missing-STRING_EXTEND issue is a real libyaml bug, but it is dead code in flvmeta's attack model.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
