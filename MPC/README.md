# MPC — Multi-Party / Multi-Agent Integration Plan

This folder contains the design and integration specs for exposing
`@pqc-sdk/core` to agent-to-agent and conversational-AI frameworks.

## Files

| File                     | Purpose                                                        |
| ------------------------ | -------------------------------------------------------------- |
| `PLAN.md`                | Full integration roadmap with phases, interfaces, and verdicts |
| `agent-tool-spec.json`   | OpenAI / Anthropic tool-call schema (JSON)                     |
| `mcp-server-spec.md`     | MCP server design (tool registration, transport, secrets)      |
| `langchain-tool-spec.md` | LangChain / LangGraph structured-tool wrapper spec             |
| `a2a-protocol.md`        | Agent-to-Agent secure channel protocol using ML-KEM + ML-DSA   |

Start with `PLAN.md`.
