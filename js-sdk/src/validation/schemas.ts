/**
 * The Concordia JSON Schemas this layer validates against, bundled as typed
 * constants so the JS package is self-contained (the Python reference loads the
 * same documents from the repo `schemas/` directory).
 *
 * These are FAITHFUL COPIES of the canonical Python-repo schemas
 * (`schemas/approval_receipt.schema.json`, `schemas/fulfillment_attestation.schema.json`)
 * and the inline message envelope schema (`concordia/schema_validator.py`
 * `_MESSAGE_SCHEMA`, derived from SPEC §4.1), with the pure-annotation keys
 * (`description` / `title` / `examples` / `$comment`) stripped. The internal
 * validator ignores those keys, so stripping them is behavior-neutral (asserted
 * against the Python reference in the parity fixtures) and keeps the bundle lean.
 *
 * GENERATED, do not hand-edit: produced from the canonical schemas. To refresh
 * after a SPEC schema change, re-run the schema-validator fixture generator's
 * emit step against the updated Python `schemas/`.
 *
 * `validate_attestation` (the §9.6 reputation-attestation schema) is NOT bundled
 * here: its schema uses `$ref` / `$defs` / `oneOf`, which the internal validator
 * does not yet support, so that surface is DEFERRED to a follow-up (boundary
 * fixture + skipped test).
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

export const APPROVAL_RECEIPT_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:approval_receipt:v0.5",
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
      "const": "ApprovalReceipt"
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "issued_at": {
      "type": "string",
      "format": "date-time"
    },
    "expires_at": {
      "type": "string",
      "format": "date-time"
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
          "minLength": 1
        },
        "role": {
          "type": "string"
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
          ]
        },
        "offer_hash": {
          "type": "string",
          "pattern": "^sha256:[a-fA-F0-9]{64}$"
        },
        "amount": {
          "type": "string"
        },
        "threshold_crossed": {
          "type": "string"
        }
      }
    },
    "references": {
      "type": "array",
      "minItems": 1,
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
            "type": "string"
          },
          "relationship": {
            "type": "string"
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
          ]
        },
        "value": {
          "type": "string",
          "minLength": 1
        }
      }
    }
  },
  "additionalProperties": true
} as const;

export const FULFILLMENT_ATTESTATION_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:fulfillment_attestation:v0.5",
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
      "const": "FulfillmentAttestation"
    },
    "id": {
      "type": "string",
      "minLength": 1
    },
    "issued_at": {
      "type": "string",
      "format": "date-time"
    },
    "agreement_attestation_id": {
      "type": "string",
      "minLength": 1
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
          ]
        },
        "settled_at": {
          "type": "string",
          "format": "date-time"
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
            "type": "string"
          },
          "relationship": {
            "type": "string"
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
      "properties": {
        "mediator_invoked": {
          "type": "boolean"
        },
        "resolution_outcome": {
          "type": "string"
        },
        "resolver_did": {
          "type": "string"
        },
        "resolution_timestamp": {
          "type": "string",
          "format": "date-time"
        },
        "fulfillment_evidence": {
          "type": "array",
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
          ]
        },
        "value": {
          "type": "string",
          "minLength": 1
        },
        "signer_did": {
          "type": "string"
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
