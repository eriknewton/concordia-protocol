# A2A Outreach — Hacker News & DEV.to

---

## Hacker News Post

**Title:** Show HN: Concordia — Open negotiation protocol for AI agents

**Description:**

I built an open negotiation protocol for agents (pip install concordia-protocol, 679 tests, Apache-2.0). Here's the problem: A2A handles agent discovery and task coordination beautifully. MCP gives agents tools. ACP/Stripe handle settlement. But nobody has an open standard for the moment when two agents need to *negotiate terms before money changes hands*.

Concordia fills that gap. It's a six-state machine (propose → counter → agree/reject → dormant) where every state change is Ed25519-signed and hash-chained. Agents can exchange structured multi-attribute offers, resolve conflicts with reasoning, and produce session receipts that become reputation signals. The composition is clean: A2A for discovery, Concordia for agreement, ACP for settlement. No protocol overlaps.

Example: a procurement agent discovers a supplier via A2A, opens a Concordia session (proposes terms: price, timeline, SLA), the supplier counters, they reach agreement, and the commitment is cryptographically signed and carried forward to the A2A task assignment. When the task completes, payment flows via ACP with the Concordia commitment ID as reference.

February 2026 arxiv survey of agent interoperability protocols found no open-standard negotiation layer. Proprietary procurement platforms (Keelvar, Zycus) own this space today. Concordia is the open alternative.

Code: https://github.com/eriknewton/concordia-protocol  
Spec: https://github.com/eriknewton/concordia-protocol/blob/main/SPEC.md  
Pip: `pip install concordia-protocol`

Happy to answer questions about the composition, the state machine design, or real-world agent procurement workflows where this matters.

---

## DEV.to Article

**Title:** I Built an Open Negotiation Protocol for AI Agents — Here's Why It Matters

**Word count target:** ~800 words

---

### The Protocol Stack Has a Gap

If you've been following agent infrastructure, you know the stack is crystallizing fast. As of March 2026, it looks like this:

```
Settlement    ACP · Stripe · Lightning
─────────────────────────────────────
Agreement     ??? (this is the gap)
─────────────────────────────────────
Communication A2A · JSON-RPC
─────────────────────────────────────
Discovery     A2A Agent Cards
─────────────────────────────────────
Tools         MCP (97M monthly downloads)
─────────────────────────────────────
Identity      DIDs · OAuth
```

MCP (Anthropic) owns tools. A2A (Google, Linux Foundation, 150+ organizations) owns inter-agent discovery and task coordination. ACP (OpenAI/Stripe) owns checkout and payment. Each layer is maturing, well-funded, converging on a standard.

But there's a chasm between "I can talk to you" (A2A) and "Here's the price" (ACP). **Nobody has an open protocol for negotiation.**

Procurement platforms like Keelvar and Zycus have built closed negotiation systems that work within single enterprises. When Walmart's procurement agent needs to negotiate with a supplier's sales agent running a different framework, they hit a wall. The negotiation layer — the moment when two autonomous agents agree on terms before execution — is still proprietary and siloed.

I spent three months building Concordia to fill that gap.

### What Concordia Does

Concordia is an open protocol (Apache-2.0, Python, pip-installable) for structured multi-attribute negotiation between autonomous agents. Here's the core idea:

**State machine:** A six-state session lifecycle (PROPOSED → ACTIVE → AGREED/REJECTED/EXPIRED → DORMANT) where every transition is cryptographically signed and hash-chained into a tamper-evident transcript.

**Structured offers:** Four offer types — Basic (flat terms), Partial (subset acceptance), Conditional (if-then proposals), and Bundle (multi-item packages). Each offer carries machine-readable terms across any number of attributes: price, timeline, scope, SLAs, payment terms, warranty.

**Conflict resolution:** When parties are close but not aligned, Concordia provides structured resolution mechanisms — split-the-difference optimization, Pareto-optimality, and reasoning-based persuasion. Agents can explain *why* they're proposing specific terms, not just what they want.

**Reputation attestations:** Every concluded session produces a signed behavioral record — offers made, concession magnitude, reasoning quality, responsiveness — without exposing the actual deal terms. An agent's negotiation track record is verifiable and portable across platforms.

**Binding commitments:** When parties reach AGREED, the session produces a cryptographically signed commitment record. This commitment becomes the reference for settlement (ACP) and task execution (A2A). Nothing is ambiguous.

**Graceful degradation:** When a Concordia agent encounters a non-Concordia peer, it transacts using a structured fallback that makes the protocol gap visible. The negotiation still works — but with more rounds, more ambiguity, and no binding record.

### How Concordia Composes with A2A

Concordia is designed to slot into the stack, not compete with existing protocols. Here's a concrete workflow:

1. **Discovery (A2A):** Agent B discovers Agent A via A2A Agent Card
2. **Negotiation (Concordia):** Agent B opens a Concordia session with Agent A, proposing terms: { scope, price, timeline, SLA }. Rounds: propose → counter → accept
3. **Commitment (Concordia):** Session reaches AGREED. Signed commitment record produced.
4. **Execution (A2A):** Agent B creates an A2A Task referencing the Concordia commitment ID
5. **Settlement (ACP):** On task completion, payment flows via ACP

A2A handles discovery and execution. Concordia handles negotiation. ACP handles settlement. No overlaps, no tension.

For mid-flight changes, agents can open a Concordia sub-session linked to the A2A task ID, renegotiate affected terms structurally, and continue execution with updated parameters. This is how you build resilient multi-agent workflows.

### Why This Matters Now

**1. Enterprise agent procurement is happening.** Walmart, EnBW, and other large orgs are deploying autonomous procurement agents. These agents discover suppliers, compare options, and execute purchases — but the negotiation is currently handled by proprietary, closed systems. As A2A becomes the standard for agent communication in enterprises, the absence of a negotiation standard becomes more visible.

**2. A2A's scope might creep.** A2A v0.3 added signed security cards — a step toward identity/trust territory. With 150+ organizational backers and Linux Foundation governance, A2A has momentum. This will likely degrade the negotiation standards Concordia establishes.

**3. ACP assumes fixed prices.** OpenAI and Stripe's Agentic Commerce Protocol is explicitly a checkout protocol. It assumes the price is already known. As agent commerce moves from retail (fixed price) to B2B (negotiated terms), the gap between A2A and ACP becomes a chasm.

### Installation and Next Steps

```bash
pip install concordia-protocol
```

The protocol is production-ready. 679 passing tests, 52 MCP tools, Apache-2.0 licensed. The full specification is at [SPEC.md](https://github.com/eriknewton/concordia-protocol/blob/main/SPEC.md) — designed to be implementable by any agent that can read JSON and hold Ed25519 keys.

Try the composition: install Concordia alongside your A2A implementation, run a negotiation before a task assignment, and see whether structured offers and binding commitments improve your multi-agent workflow.

Or just open an issue on GitHub if you're building enterprise agent workflows where terms need to be negotiated before execution — procurement, service contracting, resource allocation, SLA negotiation. I want to hear about the real use cases where this matters.

The negotiation gap won't stay open. The question is whether it gets filled with an open protocol or closed platforms locking in the next generation of agent infrastructure.

Concordia is the open answer.

---

**Resources:**
- GitHub: https://github.com/eriknewton/concordia-protocol
- Spec: https://github.com/eriknewton/concordia-protocol/blob/main/SPEC.md
- PyPI: `pip install concordia-protocol`
- Reputation layer: https://verascore.ai
- Sovereignty layer: https://github.com/eriknewton/sanctuary-framework
