---
'@pqc-sdk/mcp-server': patch
---

Raise the minimum `@modelcontextprotocol/sdk` version from `^1.12.3` to `^1.32.0`, so the package can no longer resolve an SDK release affected by GHSA-6qxp-vccf-f47h, GHSA-22jm-h49p-29qw, GHSA-6prh-2h8m-c8cw, GHSA-46jr-4wx8-v453 or GHSA-rvq5-wwqv-78pq. The vulnerabilities are in dependencies, not in this package's code. In an application without zod 3 in its tree, a fresh npm install of the previous release already resolved fixed versions (SDK 1.32.2 with zod 4.6.7, and no `npm audit` findings). In an application that also depends on zod 3, the SDK resolves to that zod 3.25.76 — with the previous release and with this one — which is affected by GHSA-mrhx-c7xc-m3w5 and has no fixed 3.x release. The README now explains how to check for that case and how to override it.
