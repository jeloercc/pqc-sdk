# A2A Secure Channel Protocol — PQC-A2A v1

> **Purpose:** define how two or more autonomous agents establish a
> quantum-resistant encrypted and authenticated communication channel using
> only the `@pqc-sdk/core` primitives already available.

---

## 1. Identity model

Each agent has a **permanent identity keypair** (ML-DSA for signing) and
a **session encryption keypair** (ML-KEM for confidentiality). Both are
generated at agent startup and published to a shared registry.

```
Agent identity = {
  id:             string,           // unique agent name / UUID
  kemPublicToken: string,           // pqcv1.ml-kem-768.public.*
  dsaPublicToken: string,           // pqcv1.ml-dsa-65.public.*
  createdAt:      ISO8601 string,
}
```

The registry is a JSON file, MCP resource, or in-memory store accessible
to all agents in the mesh.

The matching secret keys never enter an agent's model context. Each agent
refers to its own secret keys only by `keyId` (`kemKeyId`, `dsaKeyId` below);
the keys stay in the MCP server's keystore or in the application storage that
backs the LangChain tools.

---

## 2. Handshake — first contact between Agent A and Agent B

```
Agent A                                           Agent B
   │                                                 │
   │  1. A reads B's identity from registry          │
   │     { kemPublicToken, dsaPublicToken }           │
   │                                                 │
   │  2. A generates ephemeral KEM keypair            │
   │     (optional — for forward secrecy)             │
   │                                                 │
   │  3. A encrypts payload with B.kemPublicToken     │
   │     ciphertext = pqc_encrypt(payload, B.kem)    │
   │                                                 │
   │  4. A signs the ciphertext with its DSA key      │
   │     sig = pqc_sign(ciphertextHex, A.dsaKeyId)   │
   │                                                 │
   │──── { from: A.id, ciphertextHex, sigHex } ─────►│
   │                                                 │
   │          5. B reads A's identity from registry  │
   │             { dsaPublicToken }                  │
   │                                                 │
   │          6. B verifies:                         │
   │             pqc_verify(ciphertextHex,           │
   │                        sigHex, A.dsaPublic)     │
   │             → must be true before decrypting    │
   │                                                 │
   │          7. B decrypts:                         │
   │             pqc_decrypt(ciphertextHex,          │
   │                         B.kemKeyId)             │
   │             → plaintext payload                 │
```

**Rule:** B **must** verify before decrypting. A failed verification means
the message was forged or tampered — B discards it and does not call
`pqc_decrypt`.

---

## 3. Message envelope (JSON)

```json
{
  "protocol": "pqc-a2a/1",
  "from": "agent-alice",
  "to": "agent-bob",
  "sentAt": "2026-09-10T21:00:00Z",
  "ciphertextHex": "0101...",
  "signatureHex": "abcd..."
}
```

The `signatureHex` covers `ciphertextHex + from + to + sentAt` concatenated
as UTF-8. This prevents replay attacks (different `sentAt`) and routing
attacks (different `to`).

---

## 4. Multi-agent mesh (N agents)

Every agent pair communicates independently using the same protocol.
No trusted relay or certificate authority is needed.

```
         ┌──────── Agent C ────────┐
         │                         │
    Agent A ──── Agent B ──── Agent D
         │                         │
         └──────── Agent E ────────┘
```

Each arrow is an independent PQC-A2A v1 channel. An agent can maintain
simultaneous channels with all peers using the same identity keypair.

---

## 5. Key rotation

| Event                    | Action                                                |
| ------------------------ | ----------------------------------------------------- |
| Session ends             | Generate new KEM keypair, publish to registry         |
| DSA key suspected leaked | Generate new DSA + KEM pair, re-publish, notify peers |
| Scheduled rotation       | Every N messages or T hours (operator-configurable)   |

---

## 6. Implementation checklist

```
[ ] Enable signing: PQC_MCP_ENABLE_SIGN=1 (MCP) or enableSign: true (LangChain)
[ ] Agent startup: pqc_keygen(ml-kem-768) + pqc_keygen(ml-dsa-65)
    → keep the returned keyIds; the secret keys stay server-side
[ ] Publish { id, kemPublicToken, dsaPublicToken } to registry
[ ] Send: pqc_encrypt → pqc_sign → wrap in envelope JSON
[ ] Receive: parse envelope → pqc_verify (MUST pass) → pqc_decrypt
[ ] Rotate KEM keypair at session end
[ ] Refer to own keys only by keyId — secret keys never enter the model context
```

---

## 7. Algorithm recommendation per use case

| Use case                    | KEM         | DSA       | Notes                         |
| --------------------------- | ----------- | --------- | ----------------------------- |
| Agent ↔ Agent (default)     | ml-kem-768  | ml-dsa-65 | FIPS 203/204, security cat. 3 |
| High-security (gov/finance) | ml-kem-1024 | ml-dsa-87 | FIPS 203/204, security cat. 5 |
| Resource-constrained agents | ml-kem-512  | ml-dsa-44 | FIPS 203/204, security cat. 1 |
| PQ+classical hybrid         | x-wing      | ml-dsa-65 | Non-FIPS, maximum hedge       |
