---
layout: home

hero:
  name: PQC SDK
  text: Post-quantum cryptography for JS/TS
  tagline: X-Wing hybrid (X25519 + ML-KEM-768) by default, ML-KEM-768 and ML-DSA-65 (FIPS 203/204) when you need them. An API you can adopt in 30 minutes — key management and interop are still yours to design.
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
    details: pqc.encrypt and you're done. Safe defaults chosen for you — the one decision worth making, hybrid vs pure ML-KEM, is documented rather than hidden.
  - icon: 🌍
    title: Runs everywhere
    details: Node 20+, Cloudflare Workers, Deno and React Native — each verified by running the roundtrip there. No WASM, no native addons; ~26-28 KB gzip bundled, depending on what you import.
  - icon: ✅
    title: Verified, and specific about how
    details: Official NIST ACVP vectors, golden wire-format vectors, parser fuzzing, property tests and a streaming mutation matrix — each one a file you can read.
---

"Hybrid ML-KEM-768 + AES-256-GCM" above means the KEM-DEM construction — a
post-quantum KEM wrapping a symmetric cipher — not a classical+post-quantum
hybrid. [Two senses of "hybrid" →](/guide/hybrid-encryption#two-senses-of-hybrid)
