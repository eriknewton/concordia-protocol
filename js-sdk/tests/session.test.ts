import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  Session,
  InvalidTransitionError,
  InvalidSignatureError,
  InvalidMessageError,
  computeConcession,
  computeHash,
  validateChain,
  GENESIS_HASH,
  type Message,
  type PublicKeyResolver,
} from '../src/session/index.js';
import {
  SessionState,
  MessageType,
  PartyRole,
  behaviorRecordToDict,
} from '../src/types/index.js';
import { KeyPair, sign } from '../src/crypto/signing.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Fixture shape (generated FROM Python by scripts/gen-session-fixtures.py).
// ---------------------------------------------------------------------------
interface BehaviorBlock {
  raw: {
    offers_made: number;
    concessions: number;
    concession_magnitude: number;
    signals_shared: number;
    constraints_declared: number;
    constraints_violated: number;
    reasoning_provided: boolean;
    withdrawal: boolean;
    response_time_avg_seconds: number;
  };
  to_dict: Record<string, unknown>;
}

interface StepSnapshot {
  message: Message;
  expected_state: string;
  round_count: number;
  prev_hash: string;
  behaviors: Record<string, BehaviorBlock>;
  terms: unknown;
  is_terminal: boolean;
}

interface Run {
  name: string;
  session_id: string;
  add_b: boolean;
  steps: StepSnapshot[];
  final_state: string;
  round_count: number;
  concluded: boolean;
  duration_seconds: number | null;
  transcript_valid_chain: boolean;
}

interface SessionFixtures {
  seeds: {
    agent_a: { id: string; seed_hex: string; public_key_b64: string };
    agent_b: { id: string; seed_hex: string; public_key_b64: string };
  };
  genesis_hash: string;
  t0_ms: number;
  transition_table: Array<{ from: string; type: string; to: string }>;
  runs: Run[];
  lifecycle_cases: Array<{
    name: string;
    ops: string[];
    preface?: string;
    expected_state: string;
    reactivatable?: boolean;
  }>;
  invalid_transitions: Array<{
    name: string;
    state_before: string;
    message: Message;
    expected_error: string;
  }>;
  invalid_lifecycle: Array<{ name: string; state: string; expected_error: string }>;
  invalid_signatures: Array<{ name: string; message: Message; expected_error: string }>;
  unknown_type_cases: Array<{ name: string; message: Message; expected_error: string }>;
  body_shape_cases: Array<{
    name: string;
    type: string;
    preface: string | null;
    message: Message;
    accept: boolean;
    expected_state?: string;
    terms?: unknown;
    round_count?: number;
  }>;
  concession_cases: Array<{
    name: string;
    prev: Record<string, unknown>;
    curr: Record<string, unknown>;
    expected: number;
  }>;
  hash_cases: Array<{ input: Record<string, unknown>; expected_hash: string }>;
  chain_cases: Array<{ name: string; messages: Message[]; expected: boolean }>;
}

const fixtures = JSON.parse(
  readFileSync(join(__dirname, 'fixtures/session/session_vectors.json'), 'utf8'),
) as SessionFixtures;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

const KP_A = KeyPair.fromPrivateKey(hexToBytes(fixtures.seeds.agent_a.seed_hex));
const KP_B = KeyPair.fromPrivateKey(hexToBytes(fixtures.seeds.agent_b.seed_hex));
const AGENT_A = fixtures.seeds.agent_a.id;
const AGENT_B = fixtures.seeds.agent_b.id;

// Resolver mirroring the Python fixture generator's `_resolver`: known agents
// resolve to their public key, anything else returns null (rejection).
const resolver: PublicKeyResolver = (agentId) => {
  if (agentId === AGENT_A) return KP_A;
  if (agentId === AGENT_B) return KP_B;
  return null;
};

// ---------------------------------------------------------------------------
// Transition table parity.
// ---------------------------------------------------------------------------
describe('session transition table parity', () => {
  it('the JS table accepts exactly the Python-legal (from,type)->to set', () => {
    // Drive each legal transition through a fresh Session and confirm it does
    // NOT raise and lands in the expected target state. This proves the JS table
    // contains every Python entry with the same target. Because the Session API
    // does not expose the raw table, we exercise it through applyMessage by
    // forcing the from-state, then assert the resulting state.
    for (const entry of fixtures.transition_table) {
      const session = makeSessionInState(entry.from as SessionState);
      const msg = buildSignedMessage(
        entry.type as MessageType,
        senderForState(entry.from as SessionState),
        session,
      );
      const result = session.applyMessage(msg, resolver);
      expect(result).toBe(entry.to);
    }
  });

  it('rejects a sampling of illegal (from,type) pairs not in the table', () => {
    const legal = new Set(
      fixtures.transition_table.map((e) => `${e.from}|${e.type}`),
    );
    // A representative grid of pairs; any pair absent from the Python table must
    // raise InvalidTransitionError (never silently transition).
    const states: SessionState[] = [
      SessionState.PROPOSED,
      SessionState.ACTIVE,
      SessionState.AGREED,
      SessionState.REJECTED,
      SessionState.EXPIRED,
      SessionState.DORMANT,
    ];
    const types = Object.values(MessageType);
    let checked = 0;
    for (const from of states) {
      for (const type of types) {
        if (legal.has(`${from}|${type}`)) continue;
        const session = makeSessionInState(from);
        const msg = buildSignedMessage(type, senderForState(from), session);
        expect(() => session.applyMessage(msg, resolver)).toThrow(
          InvalidTransitionError,
        );
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Full Python runs replayed against the JS Session.
// ---------------------------------------------------------------------------
describe('session run parity (Python-generated transcripts)', () => {
  for (const run of fixtures.runs) {
    it(`replays run "${run.name}" with byte-identical state + behavior`, () => {
      // Clock queue: construction reads T0; if the run concludes, the
      // concluding transition reads T0 + duration*1000, reproducing Python's
      // pinned created_at / concluded_at.
      const clockValues = [fixtures.t0_ms];
      if (run.concluded && run.duration_seconds !== null) {
        clockValues.push(fixtures.t0_ms + run.duration_seconds * 1000);
      }
      let clockIdx = 0;
      const clock = () => {
        const v = clockValues[Math.min(clockIdx, clockValues.length - 1)];
        clockIdx += 1;
        return v as number;
      };

      const session = new Session({ sessionId: run.session_id, clock });
      session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
      if (run.add_b) {
        session.addParty(AGENT_B, PartyRole.RESPONDER, KP_B);
      }

      for (const step of run.steps) {
        const state = session.applyMessage(step.message, resolver);
        expect(state).toBe(step.expected_state);
        expect(session.state).toBe(step.expected_state);
        expect(session.roundCount).toBe(step.round_count);
        expect(session.prevHash).toBe(step.prev_hash);
        expect(session.isTerminal).toBe(step.is_terminal);
        expect(session.terms).toEqual(step.terms ?? null);

        // Per-agent behavior parity: raw fields AND to_dict() (which rounds
        // concession_magnitude to 4 places via pyRound).
        for (const [agentId, block] of Object.entries(step.behaviors)) {
          const b = session.getBehavior(agentId);
          expect(b.offersMade).toBe(block.raw.offers_made);
          expect(b.concessions).toBe(block.raw.concessions);
          // Raw magnitude must be bit-identical (Object.is catches any FP drift).
          expect(Object.is(b.concessionMagnitude, block.raw.concession_magnitude)).toBe(
            true,
          );
          expect(b.signalsShared).toBe(block.raw.signals_shared);
          expect(b.constraintsDeclared).toBe(block.raw.constraints_declared);
          expect(b.constraintsViolated).toBe(block.raw.constraints_violated);
          expect(b.reasoningProvided).toBe(block.raw.reasoning_provided);
          expect(b.withdrawal).toBe(block.raw.withdrawal);
          expect(
            Object.is(b.responseTimeAvgSeconds, block.raw.response_time_avg_seconds),
          ).toBe(true);
          expect(behaviorRecordToDict(b)).toEqual(block.to_dict);
        }
      }

      expect(session.state).toBe(run.final_state);
      expect(session.roundCount).toBe(run.round_count);
      // Whole-transcript hash chain validates.
      expect(validateChain(session.transcript)).toBe(run.transcript_valid_chain);

      if (run.concluded && run.duration_seconds !== null) {
        expect(session.durationSeconds()).toBe(run.duration_seconds);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// expire() / make_dormant() lifecycle parity.
// ---------------------------------------------------------------------------
describe('expire / make_dormant lifecycle parity', () => {
  for (const lc of fixtures.lifecycle_cases) {
    it(`lifecycle "${lc.name}" lands in ${lc.expected_state}`, () => {
      const session = new Session({ sessionId: `ses_${lc.name}` });
      if (lc.preface === 'open_accept') {
        session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
        session.addParty(AGENT_B, PartyRole.RESPONDER, KP_B);
        const open = buildSignedMessage(MessageType.OPEN, AGENT_A, session, {
          terms: { price: { type: 'numeric', value: 1000 } },
        });
        session.applyMessage(open, resolver);
        const accept = buildSignedMessage(
          MessageType.ACCEPT_SESSION,
          AGENT_B,
          session,
        );
        session.applyMessage(accept, resolver);
      }
      for (const op of lc.ops) {
        if (op === 'expire') session.expire();
        else if (op === 'make_dormant') session.makeDormant();
      }
      expect(session.state).toBe(lc.expected_state);
      if (lc.reactivatable !== undefined) {
        expect(session.reactivatable).toBe(lc.reactivatable);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Invalid-transition error parity (exact message text).
// ---------------------------------------------------------------------------
describe('invalid-transition error parity', () => {
  for (const tc of fixtures.invalid_transitions) {
    it(`"${tc.name}" raises InvalidTransitionError with Python text`, () => {
      // Rebuild the session up to state_before by driving the message's own
      // session_id; the message is the offending one. We reconstruct via the
      // preface implied by state_before using the same helpers.
      const session = makeSessionInState(tc.state_before as SessionState);
      expect(() => session.applyMessage(tc.message, resolver)).toThrowError(
        new InvalidTransitionError(tc.expected_error),
      );
    });
  }

  for (const lc of fixtures.invalid_lifecycle) {
    it(`"${lc.name}" raises InvalidTransitionError with Python text`, () => {
      const session = new Session({ sessionId: `ses_${lc.name}` });
      if (lc.state === 'expired') {
        session.expire();
        expect(() => session.expire()).toThrowError(
          new InvalidTransitionError(lc.expected_error),
        );
      } else if (lc.name === 'dormant_from_proposed') {
        expect(() => session.makeDormant()).toThrowError(
          new InvalidTransitionError(lc.expected_error),
        );
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Invalid-signature error parity (exact message text + fail-closed).
// ---------------------------------------------------------------------------
describe('invalid-signature error parity', () => {
  for (const sc of fixtures.invalid_signatures) {
    it(`"${sc.name}" raises InvalidSignatureError with Python text`, () => {
      const session = new Session({ sessionId: 'ses_sig' });
      session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
      session.addParty(AGENT_B, PartyRole.RESPONDER, KP_B);
      expect(() => session.applyMessage(sc.message, resolver)).toThrowError(
        new InvalidSignatureError(sc.expected_error),
      );
    });
  }
});

// ---------------------------------------------------------------------------
// Unknown MessageType -> ValueError text parity (RangeError carries the text).
// ---------------------------------------------------------------------------
describe('unknown MessageType coercion parity', () => {
  for (const uc of fixtures.unknown_type_cases) {
    it(`"${uc.name}" surfaces the Python MessageType ValueError text`, () => {
      const session = new Session({ sessionId: 'ses_unknown_type' });
      session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
      session.addParty(AGENT_B, PartyRole.RESPONDER, KP_B);
      // The message is validly signed, so signature passes and enum-coercion is
      // reached; the unknown type raises with the exact Python ValueError text.
      expect(() => session.applyMessage(uc.message, resolver)).toThrowError(
        uc.expected_error,
      );
    });
  }

  it('a missing `type` key throws like Python message["type"] KeyError', () => {
    const session = new Session({ sessionId: 'ses_no_type' });
    session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
    // Build a validly-signed message then strip its `type` so the signature
    // check passes (signature is over the no-type body) and the lookup is hit.
    const base = buildSignedMessage(MessageType.OPEN, AGENT_A, session);
    delete (base as Record<string, unknown>).type;
    // Re-sign over the type-less body so signature verification still passes.
    const resigned = reSign(base, KP_A);
    expect(() => session.applyMessage(resigned, resolver)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// body-shape parity: a present-but-non-mapping `body` is REJECTED for the
// message types whose handler reads `body.get(...)` (OPEN, OFFER, COUNTER),
// matching Python's AttributeError; an absent body or a mapping body is
// ACCEPTED; message types that never read `body` (SIGNAL) accept any body.
// Every accept/reject decision (and accepted state/terms/round_count) is
// Python-generated. The fixture messages are real Python-signed envelopes, so
// the JS Session verifies the SAME signature with the SAME keys before reaching
// the body handling.
// ---------------------------------------------------------------------------
describe('message body-shape parity (reject non-object body)', () => {
  for (const bc of fixtures.body_shape_cases) {
    it(`"${bc.name}" ${bc.accept ? 'ACCEPTS' : 'REJECTS'} (Python parity)`, () => {
      // Put a fresh session into the state the Python generator applied the
      // message in: PROPOSED for OPEN, ACTIVE (via OPEN -> ACCEPT_SESSION) for
      // OFFER/COUNTER/SIGNAL. applyMessage does NOT check prev_hash per-append
      // (intentional Python parity), so only the STATE must match for the
      // transition to be legal; the fixture message bytes are applied verbatim.
      const startState =
        bc.preface === 'active' ? SessionState.ACTIVE : SessionState.PROPOSED;
      const session = makeSessionInState(startState);

      if (bc.accept) {
        const result = session.applyMessage(bc.message, resolver);
        expect(result).toBe(bc.expected_state);
        expect(session.state).toBe(bc.expected_state);
        if (bc.terms !== undefined) {
          expect(session.terms).toEqual(bc.terms ?? null);
        }
        if (bc.round_count !== undefined) {
          // round_count is cumulative across the preface; OFFER/COUNTER bump it,
          // SIGNAL/OPEN do not. The fixture value already accounts for the
          // preface (it is read off the same Python session).
          expect(session.roundCount).toBe(bc.round_count);
        }
      } else {
        // Fail closed: a present, non-mapping body must throw rather than
        // silently coerce to {} (which would accept inputs Python rejects).
        expect(() => session.applyMessage(bc.message, resolver)).toThrow(
          InvalidMessageError,
        );
      }
    });
  }
});

// ---------------------------------------------------------------------------
// _compute_concession arithmetic parity (bit-identical doubles).
// ---------------------------------------------------------------------------
describe('computeConcession parity', () => {
  for (const cc of fixtures.concession_cases) {
    it(`"${cc.name}" -> ${cc.expected}`, () => {
      const got = computeConcession(cc.prev, cc.curr);
      expect(Object.is(got, cc.expected)).toBe(true);
    });
  }
});

// ---------------------------------------------------------------------------
// compute_hash + validate_chain parity.
// ---------------------------------------------------------------------------
describe('computeHash / validateChain parity', () => {
  it('GENESIS_HASH matches Python', () => {
    expect(GENESIS_HASH).toBe(fixtures.genesis_hash);
  });

  for (const hc of fixtures.hash_cases) {
    it(`computeHash matches Python for ${JSON.stringify(hc.input)}`, () => {
      expect(computeHash(hc.input)).toBe(hc.expected_hash);
    });
  }

  for (const ch of fixtures.chain_cases) {
    it(`validateChain "${ch.name}" -> ${ch.expected}`, () => {
      expect(validateChain(ch.messages)).toBe(ch.expected);
    });
  }
});

// ---------------------------------------------------------------------------
// Helpers: build/sign messages + force a session into a given state. These use
// only the merged crypto layer; signatures are produced (not hand-authored) so
// they verify under the same keys, matching the cross-language signing contract.
// ---------------------------------------------------------------------------

const OPEN_TERMS = {
  terms: {
    price: { type: 'numeric', value: 1000 },
    qty: { type: 'numeric', value: 10 },
  },
};

function senderForState(state: SessionState): string {
  // Any party may send most messages; A is always present. DORMANT reactivation
  // and ACTIVE messages can come from either party — A suffices for the table.
  void state;
  return AGENT_A;
}

function buildSignedMessage(
  type: MessageType,
  senderId: string,
  session: Session,
  body: Record<string, unknown> = {},
): Message {
  const kp = senderId === AGENT_A ? KP_A : KP_B;
  const msg: Record<string, unknown> = {
    concordia: '0.1.0',
    type,
    id: `msg_${Math.random().toString(16).slice(2, 10)}`,
    session_id: session.sessionId,
    timestamp: '2026-05-29T12:00:00Z',
    from: { agent_id: senderId },
    prev_hash: session.prevHash,
    body,
  };
  // Reuse the merged sign(): it strips the signature field and signs over the
  // canonical JSON, identical to Python sign_message, so the message verifies
  // under the same key the resolver returns.
  msg.signature = sign(msg, kp);
  return msg;
}

function reSign(msg: Message, kp: KeyPair): Message {
  const copy = { ...msg } as Record<string, unknown>;
  copy.signature = sign(copy, kp);
  return copy;
}

/**
 * Force a fresh Session into the given lifecycle state by driving it through the
 * minimal legal prefix, so a single offending/legal message can then be applied
 * and the resulting state/error asserted. Uses real signed messages throughout.
 */
function makeSessionInState(state: SessionState): Session {
  const session = new Session({ sessionId: `ses_force_${state}` });
  session.addParty(AGENT_A, PartyRole.INITIATOR, KP_A);
  session.addParty(AGENT_B, PartyRole.RESPONDER, KP_B);

  const apply = (type: MessageType, sender: string, body: Record<string, unknown> = {}) => {
    const m = buildSignedMessage(type, sender, session, body);
    session.applyMessage(m, resolver);
  };

  switch (state) {
    case SessionState.PROPOSED:
      // Fresh session is already PROPOSED.
      break;
    case SessionState.ACTIVE:
      apply(MessageType.OPEN, AGENT_A, OPEN_TERMS);
      apply(MessageType.ACCEPT_SESSION, AGENT_B);
      break;
    case SessionState.AGREED:
      apply(MessageType.OPEN, AGENT_A, OPEN_TERMS);
      apply(MessageType.ACCEPT_SESSION, AGENT_B);
      apply(MessageType.ACCEPT, AGENT_A);
      break;
    case SessionState.REJECTED:
      apply(MessageType.OPEN, AGENT_A, OPEN_TERMS);
      apply(MessageType.DECLINE_SESSION, AGENT_B);
      break;
    case SessionState.EXPIRED:
      session.expire();
      break;
    case SessionState.DORMANT:
      session.expire();
      session.makeDormant();
      break;
    default:
      break;
  }
  return session;
}
