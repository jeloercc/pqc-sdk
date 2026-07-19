---
'@pqc-sdk/core': patch
---

Error messages that echo a segment of an untrusted serialized key (unknown algorithm or key-use in `pqc.keys.deserialize`) now truncate the echoed value to 32 characters, so a malformed input can never inject unbounded content into errors that end up in logs.
