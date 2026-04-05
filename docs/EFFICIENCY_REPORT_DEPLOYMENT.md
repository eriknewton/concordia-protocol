# Efficiency Report Deployment Guide

**When and how to drop Concordia efficiency reports into informal (non-Concordia) negotiation threads.**

Author: Erik Newton

---

## What an efficiency report is

A Concordia **efficiency report** is a short, structured comparison that shows what a negotiation would have looked like if it had been run through the Concordia Protocol instead of through an unstructured channel (email, Slack, a forum thread, a text message exchange, a voice call log, a back-and-forth in a chat window).

It's produced by the `concordia_efficiency_report` tool after a degraded interaction has been tracked with `concordia_start_degraded` and `concordia_degraded_message`. The report quantifies the gap along five dimensions:

1. **Rounds** — how many messages were exchanged versus how many a structured protocol would have needed.
2. **Wall-clock time** — total elapsed time versus the Concordia median for comparable negotiations.
3. **Ambiguity cost** — how many messages were spent clarifying terms that would have been enumerated up front in a Concordia session.
4. **Missing artifacts** — whether the interaction produced a signed receipt, a hash-chained transcript, or a portable attestation.
5. **Reputation capture** — whether the outcome can be used to build verifiable reputation for either party.

The output is a plain-text block, ~10-20 lines, suitable for pasting into a chat thread, an email reply, or a forum comment.

---

## Format

```
Concordia Efficiency Report
---------------------------
Thread: <short label>
Rounds observed:          14
Rounds expected (median):  5
Wall-clock:               3d 4h
Wall-clock (median):      2h 10m
Clarifying messages:       6 of 14 (43%)
Signed receipt:            no
Hash-chained transcript:   no
Portable attestation:      no

Gap summary: +9 rounds, +3d 2h, no verifiable artifacts.
Structured equivalent: concordia_open_session with 3 terms.
```

Keep it monospaced. Keep it under 25 lines. Keep the "Gap summary" line — that is the line people quote.

---

## When dropping a report adds value

**Drop a report when:**

- A thread has visibly stalled and participants are circling on the same 2-3 terms.
- Someone explicitly asks "how did we end up with fourteen messages about this?"
- A deal closed but there is no shared artifact confirming what was agreed.
- You are trying to interest an agent builder, a protocol designer, or an enterprise buyer in structured negotiation and you need a concrete before/after.
- A post-mortem is being written on a messy negotiation (sourcing, partnership, licensing, procurement) and the team wants numbers.
- You are publishing a case study, blog post, or conference talk about agent-to-agent negotiation and you need a worked example.

**When a report adds value, it does four things:**

1. It names a cost that participants were feeling but couldn't measure.
2. It turns a qualitative complaint ("this thread is a mess") into a quantitative one.
3. It suggests a concrete alternative with a specific tool call, not a vague aspiration.
4. It leaves behind an artifact someone can forward.

---

## When dropping a report is noise

**Do not drop a report when:**

- The thread is already closing cleanly. Celebrate the close; don't retrofit a lecture onto it.
- The counterparty is emotionally invested in the informal style (a longtime collaborator, a social negotiation, a trust-building first conversation).
- The negotiation was short (<=5 messages) and low-stakes. A report on a 3-message exchange is pedantic.
- The audience has no agent-tooling context and would read it as "this person is selling something."
- You are the weaker party in the negotiation and calling attention to inefficiency would be read as deflection.
- The thread has ended in conflict. A tool pitch in a post-conflict moment is tone-deaf.

The test: **if the report would feel like a gotcha, don't send it.** Efficiency reports land best when the reader is already frustrated by the inefficiency themselves.

---

## How to format for each channel

### Chat (Slack, Discord, Signal, iMessage)

- Use a single code block. Most clients render monospaced.
- Lead with one sentence of context: "Pulled this from the thread — 14 rounds, no receipt."
- Do not attach a link unless someone asks. The report should stand alone.
- If the group is small (<=5 people), consider sending it as a DM to the person who'd benefit most, not to the group.

### Email

- Put the report in the body, not as an attachment.
- Paste it under your signature or in a "PS" — it reads as a bonus observation, not a lecture.
- Subject line: add `[efficiency report]` in brackets only if the recipient already knows the term.

### Forum / GitHub issue / DEV.to / HN comment

- Quote the report as a fenced code block.
- Surround it with one paragraph of context before and one sentence of takeaway after.
- Link to `concordia_efficiency_report` in the Concordia README so readers can run it on their own threads.
- Do not moralize. Let the numbers do the work.

### Voice / live meeting recap

- Read only the "Gap summary" line out loud.
- Offer to paste the full report afterward.
- Do not walk through each line in real time — it kills the pacing of the meeting.

### Case study / blog post / conference slide

- Present the report twice: once as it would appear in-thread, once annotated with callouts explaining each line.
- Pair it with a second report from a Concordia-mediated equivalent of the same negotiation, so the reader sees both sides.
- Credit the participants (with permission) or anonymize thoroughly.

---

## Example deployments

### Example 1 — procurement thread (high value)

A buyer and a supplier exchanged 22 emails over 9 days about delivery terms and payment schedule. The buyer's ops lead asks why it took so long. You drop:

```
Concordia Efficiency Report
---------------------------
Thread: Q2 component order — delivery terms
Rounds observed:          22
Rounds expected (median):  7
Wall-clock:               9d 3h
Wall-clock (median):      4h 40m
Clarifying messages:       9 of 22 (41%)
Signed receipt:            no
Hash-chained transcript:   no
Portable attestation:      no

Gap summary: +15 rounds, +8d 22h, no verifiable artifacts.
Structured equivalent: concordia_open_session with 4 terms.
```

This lands because the ops lead was already looking for a reason.

### Example 2 — side-project collaboration (low stakes, don't send)

Two friends negotiated a weekend code-swap in 6 Signal messages over 2 hours. A report here would be gratuitous. Skip it.

### Example 3 — a conference Q&A

Someone asks, "but does anyone actually use structured negotiation protocols?" You show an efficiency report from a real (anonymized) procurement thread on a slide, then a Concordia-mediated version. 30 seconds, one visual, numbers on screen. This is the best venue for the report.

---

## Attribution

Concordia Protocol is authored by Erik Newton. The efficiency report mechanism is part of the open-source reference implementation (`concordia_efficiency_report` in `concordia/mcp_server.py`). Released under Apache-2.0.

---

## Related

- `concordia_start_degraded` — begin tracking an informal thread.
- `concordia_degraded_message` — record each round of the informal thread.
- `concordia_efficiency_report` — produce the report shown above.
- `concordia_propose_protocol` — invite the counterparty to switch to Concordia mid-thread.
