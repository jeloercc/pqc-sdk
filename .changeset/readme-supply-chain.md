---
'@pqc-sdk/core': patch
'@pqc-sdk/cli': patch
'@pqc-sdk/langchain': patch
'@pqc-sdk/mcp-server': patch
---

Document the release supply chain in the README: packages are published only from the `release.yml` GitHub Actions workflow, through npm trusted publishing (OIDC) from this version on, and every version carries an npm provenance attestation that `npm audit signatures` verifies.
