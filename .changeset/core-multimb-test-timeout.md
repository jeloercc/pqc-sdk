---
'@pqc-sdk/core': patch
---

Stabilize the multi-megabyte encrypt/decrypt round-trip test against CI flakes.
It ran on the default 5s timeout, which is too tight when `turbo run test`
executes the core and CLI suites concurrently and v8 coverage instrumentation
slows the 3 MB operation under CPU contention. Give it a generous explicit
timeout so it cannot flake. Test-only; no API or runtime change.
