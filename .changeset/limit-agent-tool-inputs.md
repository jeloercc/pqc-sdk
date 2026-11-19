---
'@pqc-sdk/mcp-server': minor
'@pqc-sdk/langchain': minor
---

Limit individual tool string arguments to 2,097,152 UTF-16 code units before decoding or resolving keys.
The MCP stdio transport also caps its unparsed input buffer at 10 MiB.
LangChain hosts can supply an authorization callback for decrypt and sign operations.
MCP hosts can restrict decrypt and sign to separate key ID allowlists.
