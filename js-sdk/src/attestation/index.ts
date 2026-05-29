export {
  ATTESTATION_VERSION,
  VALIDITY_TEMPORAL_MODES,
  AttestationError,
  generateAttestation,
  generateReceiptSummary,
  computeTranscriptHash,
  validateValidityTemporal,
  isValidNow,
  type ValidityTemporal,
  type GenerateAttestationOptions,
} from './attestation.js';
