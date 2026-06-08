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

export const ATTESTATION_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:concordia:schema:attestation:v0.5",
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
      "pattern": "^\\d+\\.\\d+\\.\\d+$"
    },
    "attestation_id": {
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
    "outcome": {
      "type": "object",
      "required": [
        "status",
        "rounds",
        "duration_seconds"
      ],
      "properties": {
        "status": {
          "type": "string",
          "enum": [
            "agreed",
            "rejected",
            "expired",
            "withdrawn"
          ]
        },
        "rounds": {
          "type": "integer",
          "minimum": 0
        },
        "duration_seconds": {
          "type": "integer",
          "minimum": 0
        },
        "terms_count": {
          "type": "integer",
          "minimum": 1
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
          ]
        }
      },
      "additionalProperties": false
    },
    "parties": {
      "type": "array",
      "minItems": 2,
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
            "type": "string"
          },
          "role": {
            "type": "string",
            "enum": [
              "initiator",
              "responder",
              "mediator",
              "witness"
            ]
          },
          "behavior": {
            "type": "object",
            "properties": {
              "offers_made": {
                "type": "integer",
                "minimum": 0
              },
              "concessions": {
                "type": "integer",
                "minimum": 0
              },
              "concession_magnitude": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
              },
              "signals_shared": {
                "type": "integer",
                "minimum": 0
              },
              "constraints_declared": {
                "type": "integer",
                "minimum": 0
              },
              "constraints_violated": {
                "type": "integer",
                "minimum": 0
              },
              "reasoning_provided": {
                "type": "boolean"
              },
              "withdrawal": {
                "type": "boolean"
              },
              "response_time_avg_seconds": {
                "type": "number",
                "minimum": 0
              }
            },
            "additionalProperties": false
          },
          "signature": {
            "type": "string"
          }
        },
        "additionalProperties": false
      }
    },
    "meta": {
      "type": "object",
      "properties": {
        "category": {
          "type": "string"
        },
        "value_range": {
          "type": "string",
          "pattern": "^\\d+-\\d+_[A-Z]{3}$"
        },
        "extensions_used": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "mediator_invoked": {
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "transcript_hash": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "summary": {
      "type": "string",
      "maxLength": 1024
    },
    "fulfillment": {
      "oneOf": [
        {
          "type": "null"
        },
        {
          "$ref": "#/$defs/fulfillment_attestation"
        }
      ]
    },
    "references": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/reference"
      }
    },
    "validity_temporal": {
      "$ref": "#/$defs/validity_temporal"
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
          ]
        },
        "settled_at": {
          "type": "string",
          "format": "date-time"
        },
        "fulfilled_at": {
          "type": [
            "string",
            "null"
          ],
          "format": "date-time"
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
          ]
        },
        "delivery_confirmed": {
          "type": "boolean"
        },
        "disputes": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "term_id": {
                "type": "string"
              },
              "complainant_agent_id": {
                "type": "string"
              },
              "description": {
                "type": "string",
                "maxLength": 1024
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
          }
        },
        "counterparty_attestation": {
          "type": "object",
          "properties": {
            "agent_id": {
              "type": "string"
            },
            "confirms_fulfillment": {
              "type": "boolean"
            },
            "notes": {
              "type": "string",
              "maxLength": 512
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
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1
        },
        "type": {
          "type": "string",
          "minLength": 1
        },
        "relationship": {
          "type": "string",
          "minLength": 1
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
          "additionalProperties": false
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
          "additionalProperties": false
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
          "additionalProperties": false
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
          "additionalProperties": false
        }
      ]
    }
  }
} as const;
