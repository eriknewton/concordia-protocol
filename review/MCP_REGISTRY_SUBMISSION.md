# MCP Registry Submission — Concordia Protocol

## Status

`mcp-publisher` CLI is available (v1.5.0 via Homebrew) and `server.json` validates against the registry schema.

## What's Ready

- **`server.json`** in repo root — validated via `mcp-publisher validate`
- **README.md** contains `<!-- mcp-name: io.github.eriknewton/concordia-protocol -->` for PyPI ownership verification
- Package live on PyPI: `concordia-protocol==0.3.0`

## Publishing Steps (Erik manual — requires GitHub OAuth)

```bash
cd ~/Desktop/Claude/Concordia

# 1. Authenticate with GitHub (device flow — opens browser)
mcp-publisher login github

# 2. Publish to registry
mcp-publisher publish

# 3. Verify listing
# Visit: https://registry.modelcontextprotocol.io/servers/io.github.eriknewton/concordia-protocol
```

## PyPI Ownership Verification

The registry verifies PyPI package ownership by checking for an `mcp-name` tag in the package README. This is already added as an HTML comment at the top of `README.md`:

```html
<!-- mcp-name: io.github.eriknewton/concordia-protocol -->
```

**Important:** This tag must be present in the PyPI-published version. If the current PyPI package (0.3.0) was built before this tag was added, you may need to publish a patch release (0.3.1) or the registry may not verify ownership. Check if the registry accepts it as-is first.

## Naming Convention

With GitHub OAuth, server names must follow `io.github.<username>/<server-name>`. Our name: `io.github.eriknewton/concordia-protocol`.

Alternative: DNS-based auth allows custom domain prefixes (e.g., `ai.concordiaprotocol/negotiation`) but requires DNS TXT record verification.

## Downstream Indexing

Once published to the MCP Registry, the listing auto-indexes into:
- LobeHub MCP directory
- Smithery
- Glama.ai
- Other registry consumers

## Version Updates

When publishing new versions:

```bash
# Update version in server.json packages[0].version
# Then:
mcp-publisher publish
```
