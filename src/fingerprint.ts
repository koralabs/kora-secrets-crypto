import { blake2b256, frame } from './bytes.ts';
import {
  FINGERPRINT_EMOJI_COUNT,
  FINGERPRINT_TABLE_VERSION,
  FINGERPRINT_WORD_COUNT
} from './constants.ts';
import emojiTable from './data/fingerprint-emoji-v1.json' with { type: 'json' };
import wordTable from './data/fingerprint-words-v1.json' with { type: 'json' };

const EMOJI: readonly string[] = emojiTable;
const WORDS: readonly string[] = wordTable;

/** Human-verifiable recovery-request fingerprint, shown so a guardian can match it
 *  out-of-band against the requester before approving (crypto.md "Recovery Request
 *  Fingerprint"). */
export interface RequestFingerprint {
  version: number;
  /** 6 emoji selected from the fixed 64-entry table (6 bits each, uniform). */
  emoji: string[];
  /** 4 words selected from the fixed 256-entry table (one byte each, uniform). */
  words: string[];
}

/**
 * Derive a stable, versioned fingerprint from `policy_id || session_id || recovery_pub`.
 *
 * Preimage uses length-framed components (bytes.frame) so variable-length ids cannot be
 * re-split to collide. The 32-byte blake2b-256 digest maps to:
 * - emoji[i] = EMOJI[ digest[i] & 0x3f ]   for i in 0..5   (64 = 2^6 -> uniform)
 * - words[j] = WORDS[ digest[j] ]           for j in 0..3   (256 = 2^8 -> uniform)
 *
 * The mapping is pinned by FINGERPRINT_TABLE_VERSION; any change to tables or derivation
 * MUST bump it.
 */
export function fingerprint(policyId: string, sessionId: string, recoveryPub: Uint8Array): RequestFingerprint {
  const digest = blake2b256(frame([policyId, sessionId, recoveryPub]));

  const emoji: string[] = [];
  for (let i = 0; i < FINGERPRINT_EMOJI_COUNT; i++) {
    emoji.push(EMOJI[digest[i]! & 0x3f]!);
  }

  const words: string[] = [];
  for (let j = 0; j < FINGERPRINT_WORD_COUNT; j++) {
    words.push(WORDS[digest[j]!]!);
  }

  return { version: FINGERPRINT_TABLE_VERSION, emoji, words };
}
