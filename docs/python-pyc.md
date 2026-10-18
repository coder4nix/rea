# CPython pyc inspection

`inspect_python_pyc` / `inspect-python-pyc` answers which CPython version wrote
one selected local `.pyc` file, how its 16-byte header records source identity,
and which nested code objects marshal stored. It reads the file without running
bytecode and requires no Python installation, active binary target, Hopper,
Ghidra, or IDA.

```bash
rea inspect-python-pyc /absolute/path/to/module.pyc --json
```

The CLI resolves relative paths against the caller's working directory. MCP
requires an absolute filesystem path and preserves that exact selection:

```json
{
  "name": "inspect_python_pyc",
  "arguments": { "path": "/artifacts/module.pyc" }
}
```

## Observations

The inline Evidence result contains the artifact path, SHA-256, and byte length.
`header` contains:

- `magic`, the 16-bit little-endian field;
- `python_version` and `code_layout`, mapped from the pinned CPython 3.7–3.13
  table (`py37`, `py38`, or `py311`);
- `flags`, `hash_based`, and `check_source` from PEP 552;
- `source_hash_hex` for hash-based pycs, or `source_mtime` and `source_size`
  for timestamp pycs.

`code` is the top-level marshal code object. Nested functions remain in
`nested_code`. Each object reports name, optional qualname, filename, argument
counts, flags, names, locals (or `localsplusnames` on 3.11+), const summaries,
and bytecode length plus SHA-256.

Bytecode is not decompiled. Const strings may be truncated in the summary while
the marshal walk still consumed the original bytes.

## Limits and failures

The selected file is limited to 16 MiB by default (64 MiB maximum). Marshal
object count, nesting depth, and per-string size are bounded; exceeding a
budget fails without partial success. Magics outside the pinned 3.7–3.13 table,
truncated headers, trailing marshal bytes, and a non-code top-level object are
typed failures.

A decoded header does not prove the matching `.py` is present. `python_version`
is the magic table, not a running interpreter. This workflow does not recover
source.
