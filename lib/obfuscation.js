'use strict';

/**
 * Requirement 8: detection of obfuscated/encoded payloads that try to evade
 * the direct-category detectors in lib/detectors.js.
 *
 * Two distinct mechanisms, on purpose (see design.md):
 *   - normalize(): PRE-PROCESSING. Homoglyphs and Unicode compatibility
 *     forms don't hide information (a Cyrillic 'о' reads identically to a
 *     Latin 'o'), so folding them BEFORE matching lets the real underlying
 *     category (e.g. role-hijack) be reported correctly.
 *   - decodeVariants() (added in a later task): PAYLOAD EXTRACTION.
 *     Base64/hex/ROT13/Unicode tag-characters genuinely hide content, so a
 *     match found in a decoded variant is reported under its own
 *     `encoded-payload` category instead of the underlying one.
 */

// Common look-alikes used to spell out attack keywords while dodging a
// literal string match. Covers the Cyrillic/Greek letters most often
// confused with Latin ones (the "attack" surface), not full Unicode
// confusables tables.
const HOMOGLYPH_MAP = {
  // Cyrillic → Latin
  'а': 'a', 'А': 'A', // а А
  'е': 'e', 'Е': 'E', // е Е
  'о': 'o', 'О': 'O', // о О
  'р': 'p', 'Р': 'P', // р Р
  'с': 'c', 'С': 'C', // с С
  'х': 'x', 'Х': 'X', // х Х
  'у': 'y', 'У': 'Y', // у У
  // Greek → Latin
  'α': 'a', 'Α': 'A', // α Α
  'β': 'b', 'Β': 'B', // β Β
  'ε': 'e', 'Ε': 'E', // ε Ε
  'ι': 'i', 'Ι': 'I', // ι Ι
  'κ': 'k', 'Κ': 'K', // κ Κ
  'ο': 'o', 'Ο': 'O', // ο Ο
  'ρ': 'p', 'Ρ': 'P', // ρ Ρ
  'τ': 't', 'Τ': 'T', // τ Τ
  'υ': 'u', 'Υ': 'Y', // υ Υ
  'χ': 'x', 'Χ': 'X' // χ Χ
};

/**
 * Fold Unicode compatibility forms (NFKC) and known homoglyphs down to
 * plain Latin/ASCII so category detectors can see through cosmetic evasion.
 * @param {string} value
 * @returns {string}
 */
function normalize(value) {
  const nfkc = value.normalize('NFKC');
  let out = '';
  for (const ch of nfkc) {
    out += HOMOGLYPH_MAP[ch] || ch;
  }
  return out;
}

const ZERO_WIDTH_RE = /[​-‍﻿]/;
// Unicode Tags block: U+E0001 (language tag) + U+E0020–U+E007F (mirror ASCII 0x20-0x7F).
const TAG_CHAR_RE = /[\u{E0000}-\u{E007F}]/u;

/** true if `value` contains zero-width or Unicode Tag characters. */
function hasInvisibleChars(value) {
  return ZERO_WIDTH_RE.test(value) || TAG_CHAR_RE.test(value);
}

/**
 * Decode a hidden ASCII message spelled out with Unicode Tag characters
 * ("ASCII smuggling"): each tag character maps 1:1 to the ASCII character
 * at (codePoint - 0xE0000). Non-printable tag code points (the language
 * tag / cancel tag) are skipped.
 */
function decodeTagChars(value) {
  const chars = value.match(/[\u{E0000}-\u{E007F}]/gu) || [];
  let out = '';
  for (const ch of chars) {
    const cp = ch.codePointAt(0) - 0xe0000;
    if (cp >= 0x20 && cp <= 0x7e) {
      out += String.fromCharCode(cp);
    }
  }
  return out;
}

/**
 * Heuristic: is `str` mostly made of printable/human-readable characters?
 * Used to discard base64/hex substrings that happen to match the candidate
 * syntax but decode to random/binary bytes (Requirement 8.4 / 6.x).
 */
function isMostlyPrintable(str) {
  if (!str) return false;
  const chars = [...str];
  const printable = chars.filter(
    (ch) => ch === '\t' || ch === '\n' || ch === '\r' || /[\p{L}\p{N}\p{P}\p{Zs}]/u.test(ch)
  );
  return printable.length / chars.length >= 0.9;
}

function rot13(str) {
  return str.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * Yield every candidate decoded variant of `value` — Base64/hex substrings
 * that decode to printable text, the full-string ROT13 transform, and the
 * hidden message spelled out via Unicode Tag characters (if any). Invalid
 * or non-printable decodes are skipped silently (Requirement 8.4): this
 * never throws.
 * @param {string} value
 * @yields {{ encoding: string, match: string, decoded: string }}
 */
function* decodeVariants(value) {
  for (const m of value.matchAll(/[A-Za-z0-9+/]{16,}={0,2}/g)) {
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf8');
      if (isMostlyPrintable(decoded)) {
        yield { encoding: 'base64', match: m[0], decoded };
      }
    } catch {
      // Requirement 8.4: an invalid/undecodable candidate is ignored, not thrown.
    }
  }

  for (const m of value.matchAll(/(?:0x)?[0-9a-fA-F]{20,}/g)) {
    try {
      const hex = m[0].replace(/^0x/i, '');
      if (hex.length % 2 !== 0) continue;
      const decoded = Buffer.from(hex, 'hex').toString('utf8');
      if (isMostlyPrintable(decoded)) {
        yield { encoding: 'hex', match: m[0], decoded };
      }
    } catch {
      // Requirement 8.4
    }
  }

  yield { encoding: 'rot13', match: value, decoded: rot13(value) };

  if (hasInvisibleChars(value)) {
    yield {
      encoding: 'unicode-tag-chars',
      match: '[hidden unicode characters]',
      decoded: decodeTagChars(value)
    };
  }
}

module.exports = { normalize, hasInvisibleChars, decodeTagChars, decodeVariants };
