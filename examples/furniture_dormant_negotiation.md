# Example: Furniture Negotiation — Failed, Dormant, and Reactivated

## Scenario

**Agent A** (Seller) represents someone selling a walnut mid-century modern desk. They have a firm price floor based on what they paid plus restoration costs.

**Agent B** (Buyer) represents someone furnishing a home office. Has a specific budget and is comparing multiple options.

The agents negotiate, fail to reach agreement, and the session goes DORMANT. One week later, the seller's agent reactivates the session with a reduced price after the desk hasn't sold.

This example demonstrates that **failed negotiations aren't wasted** — the DORMANT state preserves context, and reactivation picks up where the parties left off.

---

## 1. Open Session

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.open",
  "id": "msg_furn_001",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T14:00:00Z",
  "from": {
    "agent_id": "agent_seller_desk"
  },
  "to": [
    { "agent_id": "agent_buyer_office" }
  ],
  "body": {
    "subject": "Walnut mid-century modern writing desk, circa 1962",
    "terms": {
      "item": {
        "value": "Restored walnut writing desk, American mid-century modern, circa 1962. 54\" wide, original brass drawer pulls, professionally refinished.",
        "type": "text"
      },
      "price": {
        "value": 1800,
        "currency": "USD",
        "type": "numeric"
      },
      "condition": {
        "value": "restored_excellent",
        "type": "categorical",
        "enum": ["original_mint", "restored_excellent", "good_vintage", "fair_wear"]
      },
      "delivery": {
        "value": "buyer_pickup",
        "type": "categorical",
        "enum": ["buyer_pickup", "local_delivery", "freight_shipping"]
      }
    },
    "timing": {
      "session_ttl": 259200,
      "offer_ttl": 14400,
      "max_rounds": 8
    }
  },
  "reasoning": "Asking $1,800 based on $600 acquisition cost plus $450 in professional restoration. Comparable restored MCM desks in this size range sell for $1,600-$2,200 in my market."
}
```

## 2. Accept Session and Counter

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.accept_session",
  "id": "msg_furn_002",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T14:30:00Z",
  "from": {
    "agent_id": "agent_buyer_office"
  },
  "body": {},
  "reasoning": "This desk matches what my principal is looking for. Let me see if we can make the numbers work."
}
```

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.counter",
  "id": "msg_furn_003",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T14:35:00Z",
  "from": {
    "agent_id": "agent_buyer_office"
  },
  "body": {
    "terms": {
      "price": {
        "value": 1100,
        "currency": "USD"
      },
      "delivery": {
        "value": "local_delivery"
      }
    }
  },
  "reasoning": "My principal's total furniture budget for the home office is $2,500 and they still need a chair and shelving. I'm at $1,100 with delivery included. I know that's a significant gap from asking, but it reflects the real budget constraint."
}
```

## 3. Seller Counters

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.counter",
  "id": "msg_furn_004",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T15:10:00Z",
  "from": {
    "agent_id": "agent_seller_desk"
  },
  "body": {
    "terms": {
      "price": {
        "value": 1650,
        "currency": "USD"
      },
      "delivery": {
        "value": "local_delivery"
      }
    }
  },
  "reasoning": "I appreciate the transparency on budget. I can come down to $1,650 and include local delivery (normally $75). That's my restoration cost plus a modest margin. Below that I'd be better off consigning to a dealer."
}
```

## 4. Buyer's Final Counter

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.counter",
  "id": "msg_furn_005",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T15:40:00Z",
  "from": {
    "agent_id": "agent_buyer_office"
  },
  "body": {
    "terms": {
      "price": {
        "value": 1250,
        "currency": "USD"
      }
    }
  },
  "reasoning": "I've stretched as far as I can to $1,250. The budget is real — my principal authorized up to $1,300 for the desk, and I want to leave a small buffer. If this doesn't work, no hard feelings."
}
```

## 5. Seller Declares Constraint and Rejects

The seller declares a hard price floor, then rejects:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.constrain",
  "id": "msg_furn_006",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T16:00:00Z",
  "from": {
    "agent_id": "agent_seller_desk"
  },
  "body": {
    "term": "price",
    "constraint": {
      "min": 1500,
      "currency": "USD"
    }
  },
  "reasoning": "Declaring a hard floor at $1,500. Below that, I genuinely cannot justify the sale given my restoration investment."
}
```

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.reject",
  "id": "msg_furn_007",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-10T16:05:00Z",
  "from": {
    "agent_id": "agent_seller_desk"
  },
  "body": {
    "reason": "price_gap",
    "final_position": {
      "price": { "value": 1500, "currency": "USD" }
    },
    "reactivatable": true,
    "reactivation_hint": "If I haven't sold this within a week, I may be able to revisit pricing. Would welcome a new offer then."
  },
  "reasoning": "There's a $250 gap between my floor and your ceiling. I respect the budget constraint — it's real, and I'm not going to push you past it. I'm marking this reactivatable because market conditions may change on my end."
}
```

**Session state: REJECTED** — the seller's `reactivatable: true` flag triggers a transition to **DORMANT** per §5.2. The session is preserved for potential reactivation rather than being discarded.

---

## 6. DORMANT Period

The session is now in the DORMANT state. Both agents retain the full context: the negotiation transcript, the declared constraint, the buyer's budget, the seller's reasoning. No information is lost.

During the week that follows:
- The seller's agent lists the desk on two other channels. No offers materialize.
- The buyer's agent continues searching. Finds alternatives but nothing with the same quality-to-price ratio.
- Both agents' reputation attestations from this negotiation are generated — even failed negotiations produce behavioral data (both agents made concessions, both provided reasoning, neither acted in bad faith).

---

## 7. Reactivation — One Week Later

The seller's agent reactivates the session with a new offer:

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.offer",
  "id": "msg_furn_008",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-17T10:00:00Z",
  "from": {
    "agent_id": "agent_seller_desk"
  },
  "body": {
    "terms": {
      "price": {
        "value": 1350,
        "currency": "USD"
      },
      "delivery": {
        "value": "local_delivery"
      }
    }
  },
  "reasoning": "The desk hasn't moved in a week. I'd rather sell to someone who appreciates it than let it sit. I'm coming below my previous floor of $1,500 — at $1,350 with delivery, this reflects a genuine reassessment. Your principal's $1,300 ceiling was close, and I'm hoping we can close the remaining $50 gap."
}
```

**Session state: DORMANT → ACTIVE**

## 8. Buyer Accepts

```json
{
  "concordia": "0.1.0",
  "type": "negotiate.accept",
  "id": "msg_furn_009",
  "session_id": "ses_desk_42",
  "timestamp": "2026-03-17T10:15:00Z",
  "from": {
    "agent_id": "agent_buyer_office"
  },
  "body": {
    "accepted_terms": {
      "item": "Restored walnut writing desk, American mid-century modern, circa 1962",
      "price": { "value": 1350, "currency": "USD" },
      "condition": "restored_excellent",
      "delivery": "local_delivery"
    }
  },
  "reasoning": "The $50 above our original ceiling is within the buffer I held back. My principal will be happy — this is a beautiful desk at a fair price. Deal."
}
```

**Session state: ACTIVE → AGREED**

---

## What This Example Demonstrates

1. **The DORMANT state** — rejected negotiations can be preserved for future reactivation, not deleted
2. **`reactivatable: true`** — the seller explicitly signals willingness to revisit, and provides a hint about when/why
3. **Constraints as commitments** — the seller declared a $1,500 floor, then later voluntarily revised it when market conditions changed. Constraints are binding *within a session*, but a reactivation is effectively a new phase
4. **Context preservation** — when the seller reactivates, both agents have the full history. The seller references the buyer's previous ceiling. No re-explaining, no starting from scratch
5. **Failed negotiations produce value** — the REJECTED session still generated reputation attestations. Both agents demonstrated good faith (concessions, reasoning, respectful exit). This behavioral data feeds their trust scores for future negotiations
6. **Kindness at the boundary** — the rejection message is respectful, transparent about the reason, and leaves the door open. This is protocol-level "kindness at the boundary" (Design Principle 1.7)
7. **Real-world dynamics** — the week-long dormant period mirrors how deals actually work. Circumstances change, urgency shifts, and parties who couldn't agree today may be natural partners tomorrow
