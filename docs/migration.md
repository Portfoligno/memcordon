# Migrating from memlimit 0.1.0

The compatibility form is:

```console
memcordon compat [--children] [--virtual-memory] AMOUNT COMMAND [ARG...]
```

`--children` is a deprecated no-op because descendants are included by default.
Virtual measurement is explicitly labeled and rejected when the selected
collector cannot provide it.

Unlike the old behavior, a memory-limit outcome returns `124`, remaining
descendants are cleaned up under command lifetime, and diagnostics go to
stderr. Use JSON reports when exit-code provenance matters.

