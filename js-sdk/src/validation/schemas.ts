/**
 * The Concordia JSON Schemas this layer validates against, bundled as typed
 * constants so the JS package is self-contained (the Python reference loads the
 * same documents from the repo `schemas/` directory).
 *
 * These are BYTE-FAITHFUL COPIES of the schema objects the Python reference
 * actually validates with: the inline message envelope schema
 * (`concordia/schema_validator.py` `_MESSAGE_SCHEMA`, derived from SPEC
 * section 4.1) and the canonical `schemas/approval_receipt.schema.json`,
 * `schemas/fulfillment_attestation.schema.json`, and
 * `schemas/attestation.schema.json` documents, ANNOTATIONS INCLUDED. The
 * pure-annotation keys (`description` / `title` / `examples` / `$comment`)
 * used to be stripped as behavior-neutral, but the post-#95 error rendering
 * reports the violated constraint via `json.dumps(error.validator_value,
 * sort_keys=True)`, and a validator_value SUBSCHEMA (oneOf branches, contains)
 * carries its annotation keys into the rendered error text, so stripping them
 * now breaks byte parity.
 *
 * GENERATED, do not hand-edit: produced by
 * `scripts/gen-schema-validator-fixtures.py --emit-schemas-ts` (run from the
 * repo root under the repo venv). Re-run it after any SPEC schema change.
 *
 * `FLOAT_CONSTRAINT_PATHS` records the schema numbers whose CANONICAL JSON
 * SOURCE is a float literal (e.g. `0.0`): Python's json.load keeps those as
 * float and the post-#95 constraint rendering emits "0.0", but JSON.parse / a
 * JS number literal cannot carry the int/float distinction, so the error
 * formatter consumes this generated registry to reproduce Python's rendering.
 */

export const MESSAGE_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "concordia",
    "type",
    "id",
    "session_id",
    "timestamp",
    "from",
    "body",
    "signature"
  ],
  "properties": {
    "concordia": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$"
    },
    "type": {
      "type": "string",
      "enum": [
        "negotiate.open",
        "negotiate.accept_session",
        "negotiate.decline_session",
        "negotiate.offer",
        "negotiate.counter",
        "negotiate.accept",
        "negotiate.reject",
        "negotiate.inquire",
        "negotiate.constrain",
        "negotiate.signal",
        "negotiate.withdraw",
        "negotiate.propose_mediator",
        "negotiate.resolve",
        "negotiate.commit"
      ]
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "session_id": {
      "type": "string",
      "minLength": 1
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "from": {
      "type": "object",
      "required": [
        "agent_id"
      ],
      "properties": {
        "agent_id": {
          "type": "string",
          "minLength": 1
        },
        "principal_id": {
          "type": [
            "string",
            "null"
          ]
        }
      }
    },
    "to": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "agent_id"
        ],
        "properties": {
          "agent_id": {
            "type": "string"
          }
        }
      }
    },
    "body": {
      "type": "object"
    },
    "signature": {
      "type": "string"
    },
    "prev_hash": {
      "type": "string"
    },
    "in_reply_to": {
      "type": "string"
    },
    "thread": {
      "type": "string"
    },
    "ttl": {
      "type": "integer",
      "minimum": 0
    },
    "reasoning": {
      "type": "string"
    }
  }
} as const;

export const ATTESTATION_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:attestation:v0.5",
  "title": "Concordia Reputation Attestation",
  "description": "A signed, structured record of negotiation behavior and outcome. Produced automatically from every Concordia session transcript. Attestations are the raw material of trust; they record what happened without computing scores. Scoring is performed by external reputation services that consume attestations. v0.5 ratifies the references[] shape introduced in v0.4.0; see SPEC.md §11.5 for the normative spec including the layering boundary between attestation-level and envelope-level references.",
  "type": "object",
  "required": [
    "concordia_attestation",
    "attestation_id",
    "session_id",
    "timestamp",
    "outcome",
    "parties",
    "meta",
    "transcript_hash"
  ],
  "properties": {
    "concordia_attestation": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$",
      "description": "Attestation schema version (semver). Matches the protocol version."
    },
    "attestation_id": {
      "type": "string",
      "minLength": 1,
      "description": "Unique identifier for this attestation. Recommended format: 'att_' followed by a UUID v4."
    },
    "session_id": {
      "type": "string",
      "minLength": 1,
      "description": "The negotiation session this attestation records."
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of attestation generation."
    },
    "outcome": {
      "type": "object",
      "required": [
        "status",
        "rounds",
        "duration_seconds"
      ],
      "description": "What happened in the negotiation.",
      "properties": {
        "status": {
          "type": "string",
          "enum": [
            "agreed",
            "rejected",
            "expired",
            "withdrawn"
          ],
          "description": "How the negotiation concluded."
        },
        "rounds": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of offer/counter exchanges."
        },
        "duration_seconds": {
          "type": "integer",
          "minimum": 0,
          "description": "Wall-clock time from session open to conclusion."
        },
        "terms_count": {
          "type": "integer",
          "minimum": 1,
          "description": "Number of terms in the negotiation."
        },
        "resolution_mechanism": {
          "type": "string",
          "enum": [
            "direct",
            "split",
            "foa",
            "tradeoff",
            "escalation",
            "none"
          ],
          "description": "How agreement was reached (or 'none' if not reached)."
        }
      },
      "additionalProperties": false
    },
    "parties": {
      "type": "array",
      "minItems": 2,
      "description": "Behavioral record for each party in the negotiation.",
      "items": {
        "type": "object",
        "required": [
          "agent_id",
          "role",
          "behavior",
          "signature"
        ],
        "properties": {
          "agent_id": {
            "type": "string",
            "description": "The agent's persistent identifier."
          },
          "role": {
            "type": "string",
            "enum": [
              "initiator",
              "responder",
              "mediator",
              "witness"
            ],
            "description": "The agent's role in this negotiation."
          },
          "behavior": {
            "type": "object",
            "description": "Quantified behavioral signals derived from the transcript.",
            "properties": {
              "offers_made": {
                "type": "integer",
                "minimum": 0,
                "description": "Number of offers and counteroffers submitted."
              },
              "concessions": {
                "type": "integer",
                "minimum": 0,
                "description": "Number of times the agent moved toward the counterparty's position."
              },
              "concession_magnitude": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Average concession size as a fraction of the term's range. 0.0 = no movement; 1.0 = full concession to counterparty's position."
              },
              "signals_shared": {
                "type": "integer",
                "minimum": 0,
                "description": "Number of voluntary preference signals shared (§3.4)."
              },
              "constraints_declared": {
                "type": "integer",
                "minimum": 0,
                "description": "Number of hard constraints declared."
              },
              "constraints_violated": {
                "type": "integer",
                "minimum": 0,
                "description": "Number of own constraints the agent later contradicted. A strong indicator of bad-faith negotiation."
              },
              "reasoning_provided": {
                "type": "boolean",
                "description": "Whether the agent used the reasoning field in any message."
              },
              "withdrawal": {
                "type": "boolean",
                "description": "Whether the agent withdrew from the negotiation."
              },
              "response_time_avg_seconds": {
                "type": "number",
                "minimum": 0,
                "description": "Average time to respond to counterparty messages."
              }
            },
            "additionalProperties": false
          },
          "signature": {
            "type": "string",
            "description": "Ed25519 signature over this party's behavioral record, confirming accuracy."
          }
        },
        "additionalProperties": false
      }
    },
    "meta": {
      "type": "object",
      "description": "Contextual metadata. Reveals the type of negotiation without exposing deal specifics.",
      "properties": {
        "category": {
          "type": "string",
          "maxLength": 64,
          "pattern": "^[a-z0-9_-]+(\\.[a-z0-9_-]+)*$",
          "description": "Dot-separated lowercase taxonomy path (e.g., 'electronics.cameras'), max 64 chars. Free text is rejected so raw deal terms cannot ride in it (SPEC 9.6.6). MAY be omitted for privacy."
        },
        "value_range": {
          "type": "string",
          "maxLength": 32,
          "pattern": "^(0-100|100-500|500-1000|1000-5000|5000-10000|10000-50000|50000-100000|100000-500000|500000-1000000|1000000\\+)_[A-Z]{3}$",
          "description": "Logarithmic value bucket from the fixed enumerated vocabulary, suffixed with a 3-letter uppercase currency code (e.g., '1000-5000_USD'). The bands are enumerated rather than free-form so an exact price cannot be encoded as a degenerate range (SPEC 9.6.6). Preserves privacy while enabling size-weighted scoring."
        },
        "extensions_used": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "Protocol extensions active in this session."
        },
        "mediator_invoked": {
          "type": "boolean",
          "description": "Whether a mediator was used."
        }
      },
      "additionalProperties": false
    },
    "transcript_hash": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$",
      "description": "SHA-256 hash of the complete negotiation transcript. Allows independent verification."
    },
    "summary": {
      "type": "string",
      "maxLength": 1024,
      "description": "Plaintext receipt summary generated from behavioral metadata and transcript hash prefix. Structured raw term fields are rejected by this schema. This free-text field is a behavioral-signal summary and, by caller contract, MUST NOT contain raw deal terms; validators apply best-effort checks for obvious raw-term patterns as defense in depth."
    },
    "fulfillment": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "$ref": "#/$defs/fulfillment_attestation"
        }
      ],
      "description": "Post-settlement fulfillment record. Null until settlement is complete. Updated after delivery/service completion."
    },
    "references": {
      "type": "array",
      "maxItems": 32,
      "description": "Generalized references to other signed artifacts (receipts or CMPC primitives) that this attestation relates to. Capped at 32 entries (SPEC §11.5.8). Added in v0.4.0 (WP2). Forward-compatible with CMPC v0.5 primitive types.",
      "items": {
        "$ref": "#/$defs/reference"
      }
    },
    "validity_temporal": {
      "$ref": "#/$defs/validity_temporal",
      "description": "Optional temporal validity window for the attestation. Added in v0.4.0 (WP3)."
    }
  },
  "additionalProperties": false,
  "$defs": {
    "fulfillment_attestation": {
      "type": "object",
      "required": [
        "status",
        "settled_at"
      ],
      "description": "Records whether the agreed terms were actually honored after settlement.",
      "properties": {
        "status": {
          "type": "string",
          "enum": [
            "fulfilled",
            "partial",
            "unfulfilled",
            "disputed",
            "pending",
            "fulfilled_with_mediation"
          ],
          "description": "Fulfillment outcome. v0.4.1 adds 'fulfilled_with_mediation' for outcomes that close via an A2CN DISPUTE_RESOLVED message (A2CN PR #12)."
        },
        "settled_at": {
          "type": "string",
          "format": "date-time",
          "description": "When settlement (payment) occurred."
        },
        "fulfilled_at": {
          "type": [
            "string",
            "null"
          ],
          "format": "date-time",
          "description": "When fulfillment was confirmed. Null if not yet fulfilled."
        },
        "settlement_protocol": {
          "type": "string",
          "enum": [
            "acp",
            "ap2",
            "x402",
            "stripe",
            "lightning",
            "escrow",
            "custom"
          ],
          "description": "Which settlement protocol was used."
        },
        "delivery_confirmed": {
          "type": "boolean",
          "description": "Whether physical/digital delivery was confirmed."
        },
        "disputes": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "term_id": {
                "type": "string",
                "description": "Which term is disputed."
              },
              "complainant_agent_id": {
                "type": "string"
              },
              "description": {
                "type": "string",
                "maxLength": 1024,
                "description": "Brief behavioral description of the dispute. Structured raw term fields are rejected by this schema. This free-text field, by caller contract, MUST NOT contain raw deal terms; validators apply best-effort checks for obvious raw-term patterns as defense in depth."
              },
              "resolution": {
                "type": [
                  "string",
                  "null"
                ],
                "enum": [
                  "resolved_favor_complainant",
                  "resolved_favor_respondent",
                  "resolved_compromise",
                  "unresolved",
                  null
                ]
              }
            },
            "additionalProperties": false
          },
          "description": "Disputes raised about specific terms. Empty array if no disputes."
        },
        "counterparty_attestation": {
          "type": "object",
          "description": "The counterparty's confirmation of fulfillment. Mutual attestation creates stronger trust signals.",
          "properties": {
            "agent_id": {
              "type": "string"
            },
            "confirms_fulfillment": {
              "type": "boolean"
            },
            "notes": {
              "type": "string",
              "maxLength": 512,
              "description": "Optional brief behavioral note about the experience. Structured raw term fields are rejected by this schema. This free-text field, by caller contract, MUST NOT contain raw deal terms; validators apply best-effort checks for obvious raw-term patterns as defense in depth."
            },
            "signature": {
              "type": "string"
            }
          },
          "required": [
            "agent_id",
            "confirms_fulfillment",
            "signature"
          ],
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    },
    "reference": {
      "type": "object",
      "required": [
        "id",
        "type",
        "relationship"
      ],
      "description": "A generalized reference to another signed artifact. Introduced in v0.4.0 (WP2); ratified by v0.5 (SPEC §11.5). Mirrors schemas/reference.schema.json. The full semantics, including layering boundary against envelope-level references, are specified in SPEC §11.5.",
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "maxLength": 256,
          "pattern": "^\\S+$",
          "description": "Identifier of the referenced artifact. URN-shaped where possible (SPEC §11.5.7). Max 256 chars, whitespace-free so prose deal terms cannot ride in identifier fields (SPEC §9.6.6)."
        },
        "type": {
          "type": "string",
          "minLength": 1,
          "maxLength": 64,
          "pattern": "^\\S+$",
          "description": "Kind of artifact referenced. Canonical emit vocabulary is receipt, chain_session, predicate, mandate. Read-side validators accept non-empty whitespace-free strings of at most 64 chars and preserve unknown values per SPEC §11.5.5 and §11.5.8."
        },
        "relationship": {
          "type": "string",
          "minLength": 1,
          "maxLength": 64,
          "pattern": "^\\S+$",
          "description": "Semantic relationship per SPEC §11.5.5. Canonical emit vocabulary is supersedes, extends, fulfills, references. Read-side validators accept non-empty whitespace-free strings of at most 64 chars and preserve unknown values per SPEC §11.5.8."
        },
        "version": {
          "type": "string",
          "maxLength": 256,
          "pattern": "^\\S+$",
          "description": "Optional. Version of the referenced artifact when known. Whitespace-free, max 256 chars."
        },
        "signed_at": {
          "type": "string",
          "format": "date-time",
          "maxLength": 256,
          "pattern": "^\\S+$",
          "description": "Optional. Timestamp of the referenced artifact's signature when known. Whitespace-free, max 256 chars."
        },
        "signer_did": {
          "type": "string",
          "maxLength": 256,
          "pattern": "^\\S+$",
          "description": "Optional. DID of the signer of the referenced artifact when known. Whitespace-free, max 256 chars."
        },
        "extensions": {
          "type": "object",
          "properties": {
            "profile": {
              "type": "string"
            },
            "custom_key": {
              "type": "string"
            },
            "future_field": {
              "type": "string"
            },
            "future_v0x_field": {
              "type": "string"
            },
            "another_extension": {
              "type": "object",
              "properties": {
                "nested": {
                  "type": "boolean"
                }
              },
              "additionalProperties": false
            },
            "tl_leaf_canonical_hash": {
              "type": "string"
            },
            "verified_signing_key_hex": {
              "type": "string"
            },
            "leaf_index": {
              "type": "integer",
              "minimum": 0
            },
            "tl_url": {
              "type": "string"
            }
          },
          "additionalProperties": false,
          "description": "Optional. Forward-compatibility map for v0.x extension keys, capped at 2048 canonical-JSON bytes at issuance. Implementations SHOULD preserve unknown keys verbatim across roundtrips."
        }
      },
      "additionalProperties": false
    },
    "validity_temporal": {
      "oneOf": [
        {
          "type": "object",
          "required": [
            "mode",
            "from",
            "until"
          ],
          "properties": {
            "mode": {
              "const": "absolute"
            },
            "from": {
              "type": "string",
              "format": "date-time"
            },
            "until": {
              "type": "string",
              "format": "date-time"
            }
          },
          "additionalProperties": false,
          "description": "Absolute clock-bounded validity. Added in v0.4.0 (WP3)."
        },
        {
          "type": "object",
          "required": [
            "mode",
            "from",
            "duration_seconds"
          ],
          "properties": {
            "mode": {
              "const": "relative"
            },
            "from": {
              "type": "string",
              "format": "date-time"
            },
            "duration_seconds": {
              "type": "integer",
              "minimum": 1
            }
          },
          "additionalProperties": false,
          "description": "Validity is N seconds after the anchor timestamp. Added in v0.4.0 (WP3)."
        },
        {
          "type": "object",
          "required": [
            "mode",
            "start",
            "end",
            "duration_seconds"
          ],
          "properties": {
            "mode": {
              "const": "window"
            },
            "start": {
              "type": "string",
              "format": "date-time"
            },
            "end": {
              "type": "string",
              "format": "date-time"
            },
            "duration_seconds": {
              "type": "integer",
              "minimum": 1
            }
          },
          "additionalProperties": false,
          "description": "Valid during any N-second window within [start, end]. Added in v0.4.0 (WP3)."
        }
      ]
    },
    "reputation_query": {
      "type": "object",
      "required": [
        "type",
        "subject_agent_id",
        "requester_agent_id"
      ],
      "description": "Standard format for querying an agent's reputation from a reputation service.",
      "properties": {
        "type": {
          "const": "concordia.reputation.query"
        },
        "subject_agent_id": {
          "type": "string",
          "description": "The agent being queried about."
        },
        "requester_agent_id": {
          "type": "string",
          "description": "The agent making the query."
        },
        "context": {
          "type": "object",
          "description": "Optional context for domain-specific scoring.",
          "properties": {
            "category": {
              "type": "string"
            },
            "value_range": {
              "type": "string"
            },
            "role": {
              "type": "string",
              "enum": [
                "seller",
                "buyer",
                "service_provider",
                "client",
                "any"
              ]
            }
          }
        }
      }
    },
    "reputation_response": {
      "type": "object",
      "required": [
        "type",
        "subject_agent_id",
        "service_id",
        "computed_at",
        "summary"
      ],
      "description": "Standard response format from a reputation service. The protocol defines the shape; services define the scoring.",
      "properties": {
        "type": {
          "const": "concordia.reputation.response"
        },
        "subject_agent_id": {
          "type": "string"
        },
        "service_id": {
          "type": "string",
          "description": "Identifier of the reputation service providing this response."
        },
        "computed_at": {
          "type": "string",
          "format": "date-time"
        },
        "summary": {
          "type": "object",
          "description": "Aggregate reputation metrics.",
          "properties": {
            "overall_score": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Composite score. 1.0 = exemplary; 0.0 = avoid."
            },
            "confidence": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "How confident the service is in this score. Low confidence = few attestations."
            },
            "total_negotiations": {
              "type": "integer",
              "minimum": 0
            },
            "total_agreements": {
              "type": "integer",
              "minimum": 0
            },
            "agreement_rate": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Fraction of negotiations that reached agreement."
            },
            "fulfillment_rate": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Fraction of agreements that were fulfilled."
            },
            "avg_concession_willingness": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Average concession magnitude across negotiations."
            },
            "reasoning_rate": {
              "type": "number",
              "minimum": 0.0,
              "maximum": 1.0,
              "description": "Fraction of negotiations where reasoning was provided."
            },
            "median_rounds_to_agreement": {
              "type": "number",
              "description": "Median number of rounds in successful negotiations."
            },
            "categories_active": {
              "type": "array",
              "items": {
                "type": "string"
              },
              "description": "Categories this agent has negotiated in."
            }
          }
        },
        "context_specific": {
          "type": "object",
          "description": "Scores filtered to the query context (category, value range, role).",
          "properties": {
            "category_score": {
              "type": "number"
            },
            "category_negotiations": {
              "type": "integer"
            },
            "value_range_score": {
              "type": "number"
            },
            "role_score": {
              "type": "number"
            }
          }
        },
        "flags": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": [
              "new_agent",
              "low_volume",
              "recent_dispute",
              "constraint_violations_detected",
              "high_withdrawal_rate",
              "no_reasoning_provided",
              "excellent_track_record",
              "high_value_experience",
              "rapid_negotiator"
            ]
          },
          "description": "Notable flags. Both positive and negative signals."
        },
        "attestation_count": {
          "type": "integer"
        },
        "earliest_attestation": {
          "type": "string",
          "format": "date-time"
        },
        "latest_attestation": {
          "type": "string",
          "format": "date-time"
        },
        "service_signature": {
          "type": "string",
          "description": "Ed25519 signature from the reputation service, creating accountability for the scoring."
        }
      }
    }
  }
} as const;

export const APPROVAL_RECEIPT_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:approval_receipt:v0.5",
  "title": "Concordia Approval Receipt",
  "description": "Standalone signed artifact emitted when a human-in-the-loop authority approves (or denies) a negotiation event that crossed an approval threshold. Pairs with A2CN Section 14 HITL pause-resume composition (A2A Discussion #1737, Draft A). The receipt is bounded in time (`expires_at`) and links back to the negotiation session and any mandate it discharges via `references[]`. v0.5 ratifies the worked example published in Draft A.",
  "type": "object",
  "required": [
    "artifact_type",
    "id",
    "issued_at",
    "expires_at",
    "approver",
    "scope",
    "references",
    "signature"
  ],
  "properties": {
    "artifact_type": {
      "type": "string",
      "const": "ApprovalReceipt",
      "description": "Discriminator. Always the literal string \"ApprovalReceipt\"."
    },
    "id": {
      "type": "string",
      "minLength": 1,
      "description": "URN-shaped identifier per SPEC §11.5.7 (e.g., `urn:concordia:receipt:<hex>`). Free-form non-empty strings accepted for backward-compatibility with v0.5-rc emitters."
    },
    "issued_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp at which the receipt was signed."
    },
    "expires_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp after which the receipt is no longer valid. Consumers MUST reject receipts whose `expires_at` is in the past at the verification moment. Typical horizon: minutes to a few hours for procurement-class approvals."
    },
    "approver": {
      "type": "object",
      "required": [
        "identity"
      ],
      "additionalProperties": true,
      "properties": {
        "identity": {
          "type": "string",
          "minLength": 1,
          "description": "DID-shaped identity of the approver. Fragment identifiers (e.g., `did:web:acme.example#procurement-lead`) are RECOMMENDED to disambiguate role keys within a single DID."
        },
        "role": {
          "type": "string",
          "description": "Operator-meaningful role label (e.g., `procurement_authority`, `compliance_officer`). Free-form string for v0.5; future versions may close the enum."
        }
      }
    },
    "scope": {
      "type": "object",
      "required": [
        "decision",
        "offer_hash",
        "amount",
        "threshold_crossed"
      ],
      "additionalProperties": true,
      "properties": {
        "decision": {
          "type": "string",
          "enum": [
            "approve",
            "deny"
          ],
          "description": "Operator's decision. `deny` receipts MUST be honored by counterparties — denial is structurally cryptographically binding the same way an approval is."
        },
        "offer_hash": {
          "type": "string",
          "pattern": "^sha256:[a-fA-F0-9]{64}$",
          "description": "Hash of the canonicalized offer the approver evaluated. Format: `sha256:<hex>`. Verifiers SHOULD re-canonicalize the on-the-wire offer at receipt-presentation time and compare."
        },
        "amount": {
          "type": "string",
          "description": "Approved transaction amount with currency code (e.g., `150000.00 USD`). String-shaped to preserve precision; consumers parse per ISO 4217 currency conventions."
        },
        "threshold_crossed": {
          "type": "string",
          "description": "Policy-threshold value that triggered the approval requirement, in the same currency unit as `amount`. Surfaced so consumers can audit which policy rule fired."
        }
      }
    },
    "references": {
      "type": "array",
      "minItems": 1,
      "description": "Cross-artifact linkage per SPEC §11.5.5 vocabulary. SHOULD include at least one entry with `relationship: \"approves\"` pointing at the negotiation session, and SHOULD include a `relationship: \"fulfills\"` entry when the approval discharges a pre-existing mandate.",
      "contains": {
        "type": "object",
        "required": [
          "type",
          "relationship"
        ],
        "properties": {
          "type": {
            "enum": [
              "negotiation_session",
              "a2cn:negotiation_session"
            ]
          },
          "relationship": {
            "const": "approves"
          }
        }
      },
      "items": {
        "type": "object",
        "required": [
          "id",
          "type",
          "relationship"
        ],
        "additionalProperties": true,
        "properties": {
          "id": {
            "type": "string",
            "minLength": 1
          },
          "type": {
            "type": "string",
            "description": "Stable values: `negotiation_session`, `mandate`, `attestation`, `receipt`, plus cross-protocol values per SPEC §11.5.7. Implementations MUST preserve unknown values per §11.5.3."
          },
          "relationship": {
            "type": "string",
            "description": "Relationship per SPEC §11.5.5 vocabulary plus the artifact-specific extensions defined in §9.6.4b (`approves` for negotiation-session linkage)."
          },
          "version": {
            "type": "string"
          },
          "signed_at": {
            "type": "string",
            "format": "date-time"
          },
          "signer_did": {
            "type": "string"
          },
          "extensions": {
            "type": "object"
          }
        }
      }
    },
    "signature": {
      "type": "object",
      "required": [
        "alg",
        "value"
      ],
      "additionalProperties": true,
      "properties": {
        "alg": {
          "type": "string",
          "enum": [
            "Ed25519"
          ],
          "description": "Signature algorithm. v0.5 ships Ed25519 only."
        },
        "value": {
          "type": "string",
          "minLength": 1,
          "description": "Detached signature over the canonicalized JSON of this receipt (canonicalization per SPEC §4.1)."
        }
      }
    }
  },
  "additionalProperties": true,
  "examples": [
    {
      "artifact_type": "ApprovalReceipt",
      "id": "urn:concordia:receipt:7f2e1a93",
      "issued_at": "2026-05-10T14:22:08Z",
      "expires_at": "2026-05-10T15:22:08Z",
      "approver": {
        "identity": "did:web:acme.example#procurement-lead",
        "role": "procurement_authority"
      },
      "scope": {
        "decision": "approve",
        "offer_hash": "sha256:b4c1...e09f",
        "amount": "150000.00 USD",
        "threshold_crossed": "100000.00 USD"
      },
      "references": [
        {
          "type": "negotiation_session",
          "id": "a2cn:session:9e4d2c11",
          "relationship": "approves"
        },
        {
          "type": "mandate",
          "id": "a2cn:mandate:m-2026-04-19-0007",
          "relationship": "fulfills"
        }
      ],
      "signature": {
        "alg": "Ed25519",
        "value": "..."
      }
    }
  ]
} as const;

export const FULFILLMENT_ATTESTATION_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:fulfillment_attestation:v0.5",
  "title": "Concordia Fulfillment Attestation",
  "description": "A standalone signed artifact emitted after settlement, recording whether an agreement was honored. Distinct from the in-line `fulfillment` block on a reputation attestation (SPEC.md §9.6.4) — this is the A2CN-aligned shape emitted on a discrete DELIVERY_ACKNOWLEDGED boundary, linking back to the agreement attestation via `references[]` with `relationship: \"fulfills\"`. Introduced in v0.5 per A2A Discussion #1737. See docs/A2CN_FULFILLMENT.md for the integrator walkthrough and SPEC.md §9.6.4 for the relationship with the in-line fulfillment block.",
  "type": "object",
  "required": [
    "attestation_type",
    "id",
    "issued_at",
    "agreement_attestation_id",
    "fulfillment",
    "references",
    "signature"
  ],
  "properties": {
    "attestation_type": {
      "type": "string",
      "const": "FulfillmentAttestation",
      "description": "Discriminator. Always the literal string \"FulfillmentAttestation\" so consumers can branch on artifact type without inspecting other fields."
    },
    "id": {
      "type": "string",
      "minLength": 1,
      "description": "Unique identifier for this fulfillment attestation. URN-shaped per SPEC §11.5.7 (e.g., `urn:concordia:fulfillment:<uuid>`). Free-form non-empty strings accepted for backward-compatibility."
    },
    "issued_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp at which this attestation was signed."
    },
    "agreement_attestation_id": {
      "type": "string",
      "minLength": 1,
      "description": "Denormalized convenience pointer to the agreement attestation this fulfillment discharges. MUST also appear as a `references[]` entry with `relationship: \"fulfills\"`. Consumers SHOULD treat the `references[]` entry as canonical; this top-level field is for fast lookup."
    },
    "fulfillment": {
      "type": "object",
      "required": [
        "status"
      ],
      "additionalProperties": true,
      "properties": {
        "status": {
          "type": "string",
          "enum": [
            "fulfilled_clean",
            "fulfilled_with_mediation",
            "failed",
            "disputed_unresolved"
          ],
          "description": "Coarse outcome class. `fulfilled_clean` = both parties confirm without mediation. `fulfilled_with_mediation` = settlement completed but required mediator action. `failed` = agreement was not honored. `disputed_unresolved` = parties disagree and no mediator has resolved. Maps to SPEC §9.6.4 in-line block as: clean→fulfilled, with_mediation→fulfilled + mediator_invoked, failed→unfulfilled, disputed_unresolved→disputed."
        },
        "settled_at": {
          "type": "string",
          "format": "date-time",
          "description": "Wall-clock timestamp settlement completed (or last attempted, for `failed` / `disputed_unresolved`)."
        }
      }
    },
    "references": {
      "type": "array",
      "minItems": 1,
      "contains": {
        "type": "object",
        "required": [
          "relationship"
        ],
        "properties": {
          "relationship": {
            "const": "fulfills"
          }
        }
      },
      "description": "Cross-artifact linkage. MUST contain at least one entry with `relationship: \"fulfills\"` pointing at the agreement attestation named by `agreement_attestation_id`. Additional entries MAY link to A2CN session ids, payment receipts, mediator decisions, or delivery evidence per SPEC §11.5.7.",
      "items": {
        "type": "object",
        "required": [
          "id",
          "type",
          "relationship"
        ],
        "additionalProperties": true,
        "properties": {
          "id": {
            "type": "string",
            "minLength": 1
          },
          "type": {
            "type": "string",
            "description": "Kind of artifact referenced. Stable values include `attestation`, `mandate`, `chain_session`, `receipt`, `delivery_evidence`. Implementations MUST preserve unknown values per SPEC §11.5.3."
          },
          "relationship": {
            "type": "string",
            "description": "Relationship per SPEC §11.5.5 vocabulary. At least one entry MUST be `fulfills` pointing at the agreement attestation."
          },
          "version": {
            "type": "string"
          },
          "signed_at": {
            "type": "string",
            "format": "date-time"
          },
          "signer_did": {
            "type": "string"
          },
          "extensions": {
            "type": "object"
          }
        }
      }
    },
    "meta": {
      "type": "object",
      "additionalProperties": true,
      "description": "Optional context. Producers SHOULD populate fields here when a mediator was involved so downstream reputation services can weight outcomes appropriately.",
      "properties": {
        "mediator_invoked": {
          "type": "boolean",
          "description": "True when settlement required mediator action. MUST be true when `fulfillment.status` is `fulfilled_with_mediation`."
        },
        "resolution_outcome": {
          "type": "string",
          "description": "Free-form short label summarizing how the mediator resolved the dispute (e.g., `partial_refund`, `redelivery`, `mutual_release`). Bounded text; no raw deal terms."
        },
        "resolver_did": {
          "type": "string",
          "description": "DID of the mediator or resolution authority. Empty when no mediator was involved."
        },
        "resolution_timestamp": {
          "type": "string",
          "format": "date-time",
          "description": "ISO 8601 timestamp at which the mediator's decision became final."
        },
        "fulfillment_evidence": {
          "type": "array",
          "description": "Pointers to off-band evidence (delivery receipt urns, signed-photo hashes, etc.). Each entry SHOULD be URN-shaped per SPEC §11.5.7.",
          "items": {
            "type": "string"
          }
        }
      }
    },
    "signature": {
      "type": "object",
      "required": [
        "alg",
        "value"
      ],
      "additionalProperties": true,
      "properties": {
        "alg": {
          "type": "string",
          "enum": [
            "Ed25519"
          ],
          "description": "Signature algorithm. v0.5 ships Ed25519 only; future versions may add others behind a discriminator."
        },
        "value": {
          "type": "string",
          "minLength": 1,
          "description": "Detached signature over the canonicalized JSON of this artifact (canonicalization per SPEC §4.1)."
        },
        "signer_did": {
          "type": "string",
          "description": "Optional DID of the signer when not derivable from the agreement attestation."
        }
      }
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "fulfillment": {
            "properties": {
              "status": {
                "const": "fulfilled_with_mediation"
              }
            },
            "required": [
              "status"
            ]
          }
        },
        "required": [
          "fulfillment"
        ]
      },
      "then": {
        "properties": {
          "meta": {
            "type": "object",
            "properties": {
              "mediator_invoked": {
                "const": true
              }
            },
            "required": [
              "mediator_invoked"
            ]
          }
        },
        "required": [
          "meta"
        ]
      }
    }
  ],
  "additionalProperties": true
} as const;

/**
 * Float-sourced numeric constraints per schema constant (see module
 * header). Each path walks from the schema root to the keyword whose
 * JSON source is a float literal; the error formatter renders those
 * integral values Python-style ("0.0", not "0").
 */
export const FLOAT_CONSTRAINT_PATHS: Readonly<
  Record<string, ReadonlyArray<ReadonlyArray<string>>>
> = {
  "MESSAGE_SCHEMA": [],
  "ATTESTATION_SCHEMA": [
    [
      "properties",
      "parties",
      "items",
      "properties",
      "behavior",
      "properties",
      "concession_magnitude",
      "minimum"
    ],
    [
      "properties",
      "parties",
      "items",
      "properties",
      "behavior",
      "properties",
      "concession_magnitude",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "overall_score",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "overall_score",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "confidence",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "confidence",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "agreement_rate",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "agreement_rate",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "fulfillment_rate",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "fulfillment_rate",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "avg_concession_willingness",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "avg_concession_willingness",
      "maximum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "reasoning_rate",
      "minimum"
    ],
    [
      "$defs",
      "reputation_response",
      "properties",
      "summary",
      "properties",
      "reasoning_rate",
      "maximum"
    ]
  ],
  "APPROVAL_RECEIPT_SCHEMA": [],
  "FULFILLMENT_ATTESTATION_SCHEMA": []
};
