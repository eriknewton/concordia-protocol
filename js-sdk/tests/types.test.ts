import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  SessionState,
  MessageType,
  TermType,
  Flexibility,
  OutcomeStatus,
  ResolutionMechanism,
  FulfillmentStatus,
  PartyRole,
  type AgentIdentity,
  type BehaviorRecord,
  pyRound,
  agentIdentityToDict,
  makeTimingConfig,
  behaviorRecordToDict,
  makeBehaviorRecord,
} from '../src/types/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface TypesFixtures {
  enums: Record<string, Record<string, string>>;
  agent_identity_cases: Array<{
    input: { agent_id: string; principal_id?: string | null };
    expected_dict: Record<string, unknown>;
  }>;
  timing_defaults: {
    session_ttl: number;
    offer_ttl: number;
    max_rounds: number;
  };
  behavior_defaults: Record<string, number | boolean>;
  behavior_record_cases: Array<{
    input: Record<string, number | boolean>;
    expected_dict: Record<string, unknown>;
  }>;
  round_parity: Array<{ value: number; ndigits: number; expected: number }>;
}

const fixtures = JSON.parse(
  readFileSync(join(__dirname, 'fixtures/types/types_vectors.json'), 'utf8'),
) as TypesFixtures;

// The TypeScript enum const-objects, keyed by the same name the Python
// generator emits. The values must match Python member `.value` exactly.
const TS_ENUMS: Record<string, Record<string, string>> = {
  SessionState,
  MessageType,
  TermType,
  Flexibility,
  OutcomeStatus,
  ResolutionMechanism,
  FulfillmentStatus,
  PartyRole,
};

describe('enums - value parity with Python concordia.types', () => {
  for (const [enumName, pyMap] of Object.entries(fixtures.enums)) {
    it(`${enumName} maps every member name to the Python value`, () => {
      const tsMap = TS_ENUMS[enumName];
      expect(tsMap, `TS enum ${enumName} is exported`).toBeDefined();
      // Same set of member names.
      expect(Object.keys(tsMap).sort()).toEqual(Object.keys(pyMap).sort());
      // Same value for every member.
      for (const [member, value] of Object.entries(pyMap)) {
        expect(tsMap[member]).toBe(value);
      }
    });
  }
});

describe('agentIdentityToDict - parity with AgentIdentity.to_dict()', () => {
  for (const { input, expected_dict } of fixtures.agent_identity_cases) {
    const label = JSON.stringify(input);
    it(`serializes ${label}`, () => {
      const identity: AgentIdentity = {
        agentId: input.agent_id,
        principalId: input.principal_id ?? null,
      };
      expect(agentIdentityToDict(identity)).toEqual(expected_dict);
    });
  }

  it('omits principal_id when undefined (no principal supplied)', () => {
    expect(agentIdentityToDict({ agentId: 'solo' })).toEqual({
      agent_id: 'solo',
    });
  });
});

describe('makeTimingConfig - dataclass default parity', () => {
  it('matches Python TimingConfig() field defaults', () => {
    const cfg = makeTimingConfig();
    expect(cfg.sessionTtl).toBe(fixtures.timing_defaults.session_ttl);
    expect(cfg.offerTtl).toBe(fixtures.timing_defaults.offer_ttl);
    expect(cfg.maxRounds).toBe(fixtures.timing_defaults.max_rounds);
  });

  it('applies overrides over the defaults', () => {
    const cfg = makeTimingConfig({ maxRounds: 5 });
    expect(cfg.maxRounds).toBe(5);
    expect(cfg.sessionTtl).toBe(fixtures.timing_defaults.session_ttl);
  });
});

describe('makeBehaviorRecord - dataclass default parity', () => {
  it('matches Python BehaviorRecord() field defaults', () => {
    const record = makeBehaviorRecord();
    const d = behaviorRecordToDict(record);
    expect(d).toEqual(fixtures.behavior_defaults);
  });
});

// Map the snake_case Python `input` kwargs onto a partial camelCase
// BehaviorRecord, then build a full record via the factory (which supplies
// the same defaults Python's dataclass declares).
function behaviorFromInput(
  input: Record<string, number | boolean>,
): BehaviorRecord {
  const map: Record<string, keyof BehaviorRecord> = {
    offers_made: 'offersMade',
    concessions: 'concessions',
    concession_magnitude: 'concessionMagnitude',
    signals_shared: 'signalsShared',
    constraints_declared: 'constraintsDeclared',
    constraints_violated: 'constraintsViolated',
    reasoning_provided: 'reasoningProvided',
    withdrawal: 'withdrawal',
    response_time_avg_seconds: 'responseTimeAvgSeconds',
  };
  const overrides: Partial<BehaviorRecord> = {};
  for (const [k, v] of Object.entries(input)) {
    const camel = map[k];
    if (camel === undefined) throw new Error(`unmapped behavior field: ${k}`);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (overrides as Record<string, unknown>)[camel] = v;
  }
  return makeBehaviorRecord(overrides);
}

describe('behaviorRecordToDict - parity with BehaviorRecord.to_dict()', () => {
  fixtures.behavior_record_cases.forEach(({ input, expected_dict }, i) => {
    it(`case ${i}: ${JSON.stringify(input)}`, () => {
      const record = behaviorFromInput(input);
      expect(behaviorRecordToDict(record)).toEqual(expected_dict);
    });
  });
});

describe('pyRound - bit-parity with Python round(value, ndigits)', () => {
  it(`matches Python on all ${fixtures.round_parity.length} round-parity vectors`, () => {
    const mismatches: Array<{
      value: number;
      ndigits: number;
      expected: number;
      actual: number;
    }> = [];
    for (const { value, ndigits, expected } of fixtures.round_parity) {
      const actual = pyRound(value, ndigits);
      if (!Object.is(actual, expected)) {
        mismatches.push({ value, ndigits, expected, actual });
      }
    }
    expect(mismatches).toEqual([]);
  });
});
