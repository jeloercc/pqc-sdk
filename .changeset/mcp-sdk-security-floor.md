---
'@pqc-sdk/mcp-server': patch
---

Raise the minimum `@modelcontextprotocol/sdk` version from `^1.12.3` to `^1.32.0`, so the package can no longer resolve an SDK release affected by GHSA-6qxp-vccf-f47h, GHSA-22jm-h49p-29qw, GHSA-6prh-2h8m-c8cw, GHSA-46jr-4wx8-v453 or GHSA-rvq5-wwqv-78pq. The vulnerabilities are in dependencies, not in this package's code, and a fresh npm install of the previous release already resolved fixed versions (SDK 1.32.2, with no `npm audit` findings). The README now explains that an application which also depends on zod 3 can leave the SDK on zod 3, affected by GHSA-mrhx-c7xc-m3w5 with no fixed 3.x release, and how to check for it and override it.
