---
layout: home

hero:
  name: PQC SDK
  text: Post-quantum cryptography for JS/TS
  tagline: ML-KEM-768 and ML-DSA-65 (FIPS 203/204) with safe defaults. From zero to PQC encryption in 30 minutes.
  actions:
    - theme: brand
      text: 5-minute quickstart
      link: /guide/quickstart
    - theme: alt
      text: Why PQC now?
      link: /guide/why-pqc

features:
  - icon: 🔐
    title: Zero-config
    details: pqc.encrypt and you're done. Hybrid ML-KEM-768 + AES-256-GCM with no cryptographic decisions to make.
  - icon: 🌍
    title: Runs everywhere
    details: Node 20+, Cloudflare Workers, Deno and React Native. No WASM, no native addons, ~20 KB gzip.
  - icon: ✅
    title: Validated against NIST
    details: Test suite with the official ACVP vectors for FIPS 203 and FIPS 204.
---

"Hybrid ML-KEM-768 + AES-256-GCM" above means the KEM-DEM construction — a
post-quantum KEM wrapping a symmetric cipher — not a classical+post-quantum
hybrid. [Two senses of "hybrid" →](/guide/hybrid-encryption#two-senses-of-hybrid)
