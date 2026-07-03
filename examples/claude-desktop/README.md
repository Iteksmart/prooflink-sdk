# ProofLink × Claude Desktop (MCP)

Connect Claude Desktop to the iTechSmart MCP server so Claude can verify ProofLink
receipts and query the platform directly — **65 tools**, Bearer-authenticated,
every tool call itself sealed as a ProofLink receipt.

1. Get an MCP bearer token from your iTechSmart account.
2. Merge `claude_desktop_config.json` into your config:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
3. Replace `<YOUR_MCP_BEARER_TOKEN>` and restart Claude Desktop.

Then ask Claude: *"Verify ProofLink receipt c58347c60394a21f"* or *"What's the live
UAIO platform status?"* — Claude calls the MCP tools and shows the cryptographic result.

Endpoint: `https://mcp.itechsmart.dev/sse` (SSE transport, auth required at connect).
