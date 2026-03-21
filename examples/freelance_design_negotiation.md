# Example: Freelance Design Services Negotiation

## Scenario

**Agent A** (Buyer) represents a startup founder looking to hire a brand identity designer for a product launch. Budget is flexible but tight. Launch date is firm.

**Agent B** (Seller) represents a freelance designer with a strong portfolio. Currently has partial availability — could take the project on a compressed timeline for a premium, or a relaxed timeline at standard rates.

**Negotiated terms:** scope, rate, timeline, revision rounds, and IP ownership.

This example demonstrates preference signals, the `reasoning` field driving creative deal-making, and a conditional offer where rate depends on timeline.

---

## 1. Open Session

Agent A proposes the negotiation, defining the term space:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.open",
  "id": "msg_f1a00001",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T09:00:00Z",
  "from": {
    "agent_id": "agent_buyer_startup"
  },
  "to": [
    { "agent_id": "agent_designer_mira" }
  ],
  "body": {
    "subject": "Brand identity design for product launch",
    "terms": {
      "scope": {
        "value": "Logo, color palette, typography, and brand guidelines document",
        "type": "text"
      },
      "rate": {
        "value": 3500,
        "currency": "USD",
        "type": "numeric",
        "label": "Flat project rate"
      },
      "timeline": {
        "value": "2026-04-18",
        "type": "temporal",
        "label": "Final delivery date"
      },
      "revisions": {
        "value": 2,
        "type": "numeric",
        "label": "Rounds of revisions included"
      },
      "ip_ownership": {
        "value": "full_transfer",
        "type": "categorical",
        "enum": ["full_transfer", "exclusive_license", "non_exclusive_license"],
        "label": "IP ownership on completion"
      }
    },
    "timing": {
      "session_ttl": 172800,
      "offer_ttl": 7200,
      "max_rounds": 10
    }
  },
  "reasoning": "We're launching May 1st and need brand assets locked by mid-April. Budget is startup-stage — we can't do agency rates, but we value quality and will be straightforward about what we can pay."
}
```

## 2. Accept Session

Agent B agrees to negotiate:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.accept_session",
  "id": "msg_f1a00002",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T09:12:00Z",
  "from": {
    "agent_id": "agent_designer_mira"
  },
  "body": {},
  "reasoning": "Interested. The scope is clear and the timeline is workable. Let me review the terms."
}
```

## 3. Counter with Preference Signal

Agent B counters on rate and revisions, and shares a preference signal to accelerate convergence:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.counter",
  "id": "msg_f1a00003",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T09:25:00Z",
  "from": {
    "agent_id": "agent_designer_mira"
  },
  "body": {
    "terms": {
      "rate": {
        "value": 5200,
        "currency": "USD"
      },
      "revisions": {
        "value": 3
      },
      "ip_ownership": {
        "value": "exclusive_license"
      }
    }
  },
  "reasoning": "My standard rate for this scope is $5,200, which includes three revision rounds. I'd prefer an exclusive license rather than full transfer — it lets me include this in my portfolio, which matters a lot for my business. Full transfer is possible but would need to be reflected in the rate. Timeline of April 18th works."
}
```

Agent B also sends a preference signal:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.signal",
  "id": "msg_f1a00004",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T09:26:00Z",
  "from": {
    "agent_id": "agent_designer_mira"
  },
  "body": {
    "priority_ranking": ["ip_ownership", "rate", "revisions", "timeline", "scope"],
    "flexibility": {
      "rate": "somewhat_flexible",
      "revisions": "very_flexible",
      "timeline": "somewhat_flexible",
      "ip_ownership": "firm",
      "scope": "firm"
    }
  },
  "reasoning": "Being transparent: portfolio rights matter most to me. I have real flexibility on revision count and some room on rate if we can agree on exclusive license."
}
```

## 4. Counter with Creative Conditional Offer

Agent A, informed by the preference signal, constructs a conditional offer linking rate to timeline:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.counter",
  "id": "msg_f1a00005",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T10:05:00Z",
  "from": {
    "agent_id": "agent_buyer_startup"
  },
  "body": {
    "conditions": [
      {
        "if": { "timeline": "2026-04-11" },
        "then": {
          "rate": { "value": 4800, "currency": "USD" },
          "revisions": { "value": 2 }
        }
      },
      {
        "if": { "timeline": "2026-04-18" },
        "then": {
          "rate": { "value": 4400, "currency": "USD" },
          "revisions": { "value": 3 }
        }
      }
    ],
    "terms": {
      "ip_ownership": {
        "value": "exclusive_license"
      }
    }
  },
  "reasoning": "I hear you on the portfolio rights — exclusive license works for us. Here's a creative option: if you can deliver a week early (April 11), I can go to $4,800 because early delivery has real value for our launch prep. If you keep the original April 18 date, I'm at $4,400 but I'll add a third revision round. Either way, I'm conceding significantly on rate and fully accepting your IP preference."
}
```

## 5. Inquire

Agent B asks a clarifying question before responding:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.inquire",
  "id": "msg_f1a00006",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T10:20:00Z",
  "from": {
    "agent_id": "agent_designer_mira"
  },
  "body": {
    "about_term": "scope",
    "question": "Does the brand guidelines document include social media templates and business card layout, or just the core identity system (logo, palette, type)?"
  },
  "reasoning": "The answer affects whether I can hit April 11th. Core identity — yes, easily. With social templates it's tight."
}
```

## 6. Clarification Response

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.offer",
  "id": "msg_f1a00007",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T10:35:00Z",
  "from": {
    "agent_id": "agent_buyer_startup"
  },
  "body": {
    "terms": {
      "scope": {
        "value": "Core identity system: logo (primary + icon), color palette, typography selection, and a 4-6 page brand guidelines PDF. No social templates needed at this stage."
      }
    }
  },
  "reasoning": "Core identity only. We'll handle social templates in-house once the brand system is established."
}
```

## 7. Accept

Agent B accepts the early-delivery option:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.accept",
  "id": "msg_f1a00008",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T10:50:00Z",
  "from": {
    "agent_id": "agent_designer_mira"
  },
  "body": {
    "accepted_terms": {
      "scope": "Core identity system: logo (primary + icon), color palette, typography selection, and a 4-6 page brand guidelines PDF",
      "rate": { "value": 4800, "currency": "USD" },
      "timeline": "2026-04-11",
      "revisions": 2,
      "ip_ownership": "exclusive_license"
    }
  },
  "reasoning": "With scope confirmed as core identity only, I can comfortably hit April 11th. $4,800 with exclusive license is a fair deal — you get early delivery for your launch, I keep portfolio rights. Two revisions is fine for a focused scope like this."
}
```

## 8. Commit

Both agents sign the agreement:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.commit",
  "id": "msg_f1a00009",
  "session_id": "ses_design_01",
  "timestamp": "2026-03-21T10:52:00Z",
  "from": {
    "agent_id": "agent_buyer_startup"
  },
  "body": {
    "agreement": {
      "terms": {
        "scope": "Core identity system: logo (primary + icon), color palette, typography selection, and a 4-6 page brand guidelines PDF",
        "rate": { "value": 4800, "currency": "USD" },
        "timeline": "2026-04-11",
        "revisions": 2,
        "ip_ownership": "exclusive_license"
      },
      "transcript_hash": "sha256:a4b8c2d6e0f1...",
      "settlement_ref": {
        "protocol": "stripe_connect",
        "details": {
          "milestone_1": { "amount": 2400, "trigger": "project_start" },
          "milestone_2": { "amount": 2400, "trigger": "final_delivery_approved" }
        }
      }
    }
  },
  "reasoning": "Confirmed. Payment split 50/50 between project start and final delivery approval via Stripe Connect."
}
```

---

## What This Example Demonstrates

1. **Multi-attribute negotiation** — five terms negotiated simultaneously, not just price
2. **Preference signals** — Agent B's signal revealed that IP ownership mattered most, enabling Agent A to make a creative concession
3. **Conditional offers** — rate linked to timeline, letting both agents choose the trade-off that works best
4. **The `reasoning` field** — every message explains *why*, turning a protocol exchange into a productive conversation
5. **The `inquire` message** — agents can ask questions mid-negotiation without making offers, gathering information to make better proposals
6. **Value creation** — the final deal ($4,800 with early delivery and exclusive license) is better for *both* parties than the opening positions suggested: the buyer gets the assets a week earlier for their launch, the designer gets a higher rate than offered and keeps portfolio rights
