# PR Bodies — GitHub Pull Requests

Pega estos textos directamente en GitHub al abrir cada PR.

---

## PR 1: feat/ml-kem-512-1024 → main

**Title:** `feat(core): expose ML-KEM-512 and ML-KEM-1024, close FIPS 203 F203-01`

**Body:**

```markdown
## Summary

Exposes all three FIPS 203 ML-KEM parameter sets alongside the existing
ML-KEM-768, closing compliance finding **F203-01** (PARTIALLY CONFORMING →
CONFORMING).

| Parameter set | Security category | Envelope       | pk / sk / ct bytes |
| ------------- | ----------------- | -------------- | ------------------ |
| ML-KEM-512    | 1 (≈ AES-128)     | v3 `0x03/0x03` | 800 / 1632 / 768   |
| ML-KEM-768    | 3 (≈ AES-192)     | v1 `0x01/0x01` | 1184 / 2400 / 1088 |
| ML-KEM-1024   | 5 (≈ AES-256)     | v4 `0x04/0x04` | 1568 / 3168 / 1568 |

## API changes (additive — no breaking changes)

- `KemAlgorithm` widened to `'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024' | 'x-wing'`
- `SUPPORTED_ALGORITHMS` includes all three ML-KEM sets
- `FIPS_ALGORITHMS` constant added — lists ML-KEM-512/768/1024 + ML-DSA, excludes `x-wing`
- Streaming version bytes 5 (ML-KEM-512) and 6 (ML-KEM-1024) registered
- All existing v1/v2 serialized artifacts remain byte-identical

## Test coverage

- `nist-vectors.test.ts` — parametrised loop over all 3 sets, 50 new FIPS 203 ACVP KAT cases
- `golden-vectors-v3.test.ts` + `golden-serialization-v3.json` — stability lock for ML-KEM-512 envelope
- `golden-vectors-v4.test.ts` + `golden-serialization-v4.json` — stability lock for ML-KEM-1024 envelope
- Total: **446 tests passing**, 98%+ coverage, 10/10 turbo gate

## Compliance

- `docs/compliance/FIPS-203-MATRIX.md`: F203-01 closed
- `docs/serialization-format.md`: §2.3, §2.4, §9.1 added
- Both new sets use the same vendored primitive as ML-KEM-768, inheriting
  all FIPS 203 corrections (F203-11, F203-18, F203-19)

## Merge order

Merge this **after** `fix/fips-corrective-pass-2`.
```

---

## PR 2: fix/fips-corrective-pass-2 → main

**Title:** `fix(core): FIPS 203/204 corrective pass 2`

**Body:**

````markdown
## Summary

Second corrective pass closing multiple FIPS 203/204 compliance findings
and adding two new public API surface items.

## New public API

### `collectDecryptStream(secretKey, ciphertext)`

Buffering wrapper around `decryptStream`. Only returns the full plaintext
after the **entire** stream authenticates — never yields partial output on
truncation or tampering. Safe default for agents and short payloads.

```ts
const plaintext = await pqc.collectDecryptStream(pair.secretKey, source());
```
````

Use `decryptStream` directly only for very large payloads that cannot be
buffered.

### `FIPS_ALGORITHMS` / `FipsAlgorithm`

Exported constant listing only the NIST-standardized algorithms
(`ml-kem-768`, `ml-dsa-44/65/87`). `x-wing` is excluded — it is a
CFRG Internet-Draft construction, not a FIPS 203 parameter set (§3.3).

```ts
import { FIPS_ALGORITHMS } from '@pqc-sdk/core';
FIPS_ALGORITHMS.includes('ml-kem-768'); // true
FIPS_ALGORITHMS.includes('x-wing'); // false
```

## Behavior changes

- **F204-06/07:** `pqc.keys.generate()` and `pqc.sign()` now throw
  `PqcError('RBG_FAILURE')` on platform RBG failure — matching existing
  ML-KEM behavior (F203-11). Previously they leaked a raw host error.
- **F204-09:** `sign()` draws the 32-byte hedged `rnd` through
  `sampleRandomness` and zeroes it in a `finally` block after use.
  Signing remains hedged — `rnd` is never caller-supplied.
- `pqc.keys.generate({ algorithm: 'ml-dsa-44' })` emits a one-time
  `console.warn` (security category 2 — prefer ml-dsa-65).

## New test files

| File                                 | Closes                                                                                                                |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| `fips203-input-checks.test.ts`       | F203-05 (§7.2 modulus check), F203-10 (§7.3 H(ek) hash check) — converts two CONFORMING (delegated) rows to evidenced |
| `provider-tripwires.test.ts`         | F204-21 (SHAKE256/128 NIST KAT vectors), F204-09 (hedged-signing freshness + non-aliasing), X-Wing upgrade guard      |
| `rbg-attribution.test.ts` (extended) | F204-06/07 (ML-DSA keygen/sign RBG-failure suite)                                                                     |

## Compliance matrix changes

**FIPS-203-MATRIX.md:**

- F203-03: INDETERMINATE → **CONFORMING** (`FIPS_ALGORITHMS` boundary)
- F203-05: CONFORMING (delegated) → **CONFORMING** (evidenced)
- F203-10: CONFORMING (delegated) → **CONFORMING** (evidenced)

**FIPS-204-MATRIX.md:**

- F204-05: → **CONFORMING** (hedged `rnd` freshness evidenced)
- F204-06: → **CONFORMING** (keygen RBG failure attribution)
- F204-07: → **CONFORMING** (sign RBG failure attribution)
- F204-21: → **CONFORMING** (SHAKE KAT tripwires)

## Test results

416 tests passing · 97.6% coverage · 10/10 turbo gate · 0 lint errors

## Merge order

Merge this **before** `feat/ml-kem-512-1024`.

```

```
