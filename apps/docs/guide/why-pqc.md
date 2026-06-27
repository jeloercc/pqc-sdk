# Why PQC now?

The short answer: because the regulatory deadlines have already started, and
because data encrypted today with RSA/ECC can be harvested today and decrypted
once a relevant quantum computer exists (_harvest now, decrypt later_).

## The problem

A quantum algorithm from 1994 (Shor) breaks all deployed public-key
cryptography: RSA, ECDSA, ECDH, Ed25519. No quantum computer capable of running
it at scale exists yet — but any long-lived data (medical records, industrial
secrets, diplomatic communications) captured today is retroactively exposed the
day one does.

NIST standardized the answer in August 2024: **FIPS 203 (ML-KEM)** for key
exchange, **FIPS 204 (ML-DSA)** and **FIPS 205 (SLH-DSA)** for signatures. This
SDK implements **FIPS 203 (ML-KEM-768)** and **FIPS 204 (ML-DSA-65)** today;
SLH-DSA (FIPS 205) is on the roadmap, not yet implemented.

## The deadlines

### CNSA 2.0 (NSA, US national security systems)

| Date           | Milestone                                                   |
| -------------- | ----------------------------------------------------------- |
| **Jan 1 2027** | Every **new acquisition** for NSS must support CNSA 2.0     |
| 2030           | Network equipment (VPNs, routers) exclusively PQC           |
| 2031           | Mandatory use across all covered categories                 |
| 2033           | Operating systems and custom applications exclusively PQC   |
| 2035           | Full migration (NSM-10): zero quantum-vulnerable algorithms |

CNSA 2.0 requires the highest parameter sets (ML-KEM-1024, ML-DSA-87). For
general use outside NSS, NIST endorses the parameters this SDK uses by default
(ML-KEM-768, ML-DSA-65), the standard security/size balance.

### NIST IR 8547 (the entire US federal government, and de facto the industry)

- **2030–2031**: RSA, ECDSA, ECDH and DSA become **deprecated**.
- **2035**: they become **disallowed** in federal systems.

Australia (ASD) is more aggressive: it bans classical cryptography in
government systems **after 2030**. The EU recommended that member states have
transition plans and high-risk cases migrated by 2030.

## What it means for your app

1. **If your data must still be secret in 2035**, encrypting it today with
   RSA/ECDH is already technical debt with compound interest. Key exchange is
   the first thing to migrate (it is what's vulnerable to _harvest now,
   decrypt later_).
2. **If you sell to the public sector** (US, EU, Australia), PQC procurement
   requirements are already entering tenders — in the US, starting January 2027.
3. **Signatures are less urgent** (an attacker needs the quantum computer
   _before_ what was signed expires), but everything signed with a long
   lifetime — firmware, software updates, root certificates — is already
   migrating.

## Starting today costs little

```ts twoslash
import { pqc } from '@pqc-sdk/core';

const pair = await pqc.keys.generate();
const ciphertext = await pqc.encrypt('ready for 2035', pair.publicKey);
```

And to find out how much pre-quantum crypto your codebase has today:

```bash
npx @pqc-sdk/cli audit
```

`audit` is a heuristic, best-effort regex scan — a quick first pass that can
have false positives and false negatives, not an exhaustive guarantee.

Sources: [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) ·
[NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) ·
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) ·
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
