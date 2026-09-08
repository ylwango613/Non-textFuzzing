The `bytestream2_put_*` functions use bounds-checked writes (set `p->eof = 1` instead of overflowing), and `av_image_check_size` protects the `tex_size` integer computation from overflow. No exploitable memory safety issues remain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
