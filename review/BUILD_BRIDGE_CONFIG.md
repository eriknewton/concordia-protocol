# BUILD SPEC: Configure Concordia Sanctuary Bridge

**Status:** READY TO BUILD — Mac Mini session
**Priority:** #4 (enables cryptographic binding of negotiations to sovereign identity)
**Estimated time:** 1-2 hours
**Date:** April 8, 2026

---

## Problem

The Concordia Sanctuary Bridge exists in both codebases but is currently disabled on the Mac Mini deployment:
- Concordia reports 48 tools operational
- Sanctuary Bridge shows 0 identity mappings
- Running standalone — no cryptographic binding between negotiation transcripts and the agent's sovereign identity

This means negotiations are signed with Concordia's Ed25519 key but NOT committed to Sanctuary's L3 layer, NOT audit-logged through Sanctuary's encrypted audit trail, and NOT linked to the agent's L4 reputation.

---

## What the Bridge Does (Architecture Recap)

**Sanctuary side** (`server/src/bridge/`):
- `bridge_commit`: Canonicalize Concordia outcome → create L3 SHA-256 commitment + optional Pedersen commitment → Ed25519 sign
- `bridge_verify`: Recompute hash from revealed outcome → verify signature
- `bridge_attest`: Create L4 attestation linking outcome to reputation

**Concordia side** (`concordia/sanctuary_bridge.py`):
- Payload builder that produces correctly-shaped requests for Sanctuary's `proof_commitment` and `reputation_record` tools
- Does NOT call Sanctuary directly — generates payloads that a client forwards

---

## Configuration Steps

### Step 1: Verify both servers are running

```bash
# Check Sanctuary is loaded in OpenClaw with bridge tools
# Look for bridge_commit, bridge_verify, bridge_attest in tool list

# Check Concordia's tool list includes bridge-related tools
cd ~/Desktop/Claude/Concordia
python -m concordia --list-tools 2>/dev/null | grep bridge
```

### Step 2: Create identity mapping

The bridge needs to know which Concordia agent_id maps to which Sanctuary DID. On the Mac Mini:

```bash
# Get Sanctuary's DID
# (from the Ed25519 key at ~/.sanctuary/identity/)

# Get Concordia's agent_id
# (from the running Concordia session config)
```

The identity mapping configuration should be at:
```
~/.concordia/bridge-config.json
```

```json
{
  "sanctuary_bridge": {
    "enabled": true,
    "sanctuary_endpoint": "stdio",
    "identity_mappings": [
      {
        "concordia_agent_id": "<concordia-agent-id>",
        "sanctuary_did": "<did:key:z6Mk...>",
        "auto_commit": true,
        "auto_attest": true
      }
    ],
    "commitment_options": {
      "use_pedersen": true,
      "store_in_l4": true
    }
  }
}
```

### Step 3: Test the bridge end-to-end

1. Start a test Concordia negotiation session
2. Complete the session (reach AGREED state)
3. Verify the bridge payload is generated
4. Forward the payload to Sanctuary's `bridge_commit`
5. Verify the L3 commitment is stored
6. Verify the L4 attestation is created
7. Check Sanctuary's audit log for the bridge operation

### Step 4: Verify Verascore pipeline

After bridge is configured:
1. Complete a Concordia negotiation
2. Bridge commits to Sanctuary L3
3. Bridge attests to Sanctuary L4
4. Sanctuary publishes SHR to Verascore (includes negotiation attestation)
5. Verascore score reflects Concordia negotiation competence

This closes the full loop: negotiate → commit → attest → publish → score.

---

## Code Changes Needed

### Concordia side

Check if `concordia/sanctuary_bridge.py` reads the config file:

```python
# Expected: bridge reads config from ~/.concordia/bridge-config.json
# If not, add config reader
```

Check if the bridge auto-triggers on session completion:

```python
# In session.py or mcp_server.py:
# When session transitions to AGREED, check if bridge is enabled
# If enabled, generate commitment payload and forward to Sanctuary
```

### Sanctuary side

The bridge tools (`bridge_commit`, `bridge_verify`, `bridge_attest`) should already work — they were built in Phase 4 and tested. Verify they're registered and accessible via OpenClaw.

---

## Verification

After configuration:

| Check | Expected |
|-------|----------|
| `bridge_config` tool returns | `enabled: true`, 1+ identity mappings |
| Concordia session AGREED | Bridge payload generated automatically |
| Sanctuary L3 | Commitment stored with session hash |
| Sanctuary L4 | Attestation created linking to session |
| Sanctuary audit log | Bridge operations logged |
| Verascore publish | SHR includes negotiation attestation count |

---

## Dependencies

- Sanctuary must be running with bridge tools registered (67 tools — confirm after wrapper fix pull)
- DID mismatch must be resolved first (priority #3) so the bridge uses the correct identity
- Tool name mangling fix (priority #1) must land so bridge tools are callable through OpenClaw
