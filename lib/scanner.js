'use strict';

const builtInDetectors = require('./detectors');
const { normalize, decodeVariants, hasInvisibleChars } = require('./obfuscation');

const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };
const HIDDEN_CHARS_MATCH = '[hidden unicode characters]';

function maxSeverity(a, b) {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Returns the first match of `value` against a list of regex patterns.
 */
function firstMatch(value, patterns) {
  for (const pattern of patterns) {
    // Clone without the global flag to avoid shared lastIndex state.
    const re = new RegExp(pattern.source, pattern.flags.replace('g', ''));
    const m = re.exec(value);
    if (m) {
      return m[0];
    }
  }
  return null;
}

/**
 * Normalizes a custom validator into the internal detector shape.
 *
 * Accepted forms:
 *   addValidator('name', /regex/)
 *   addValidator('name', { pattern: /regex/, severity, message, type })
 *   addValidator('name', { patterns: [/a/, /b/], ... })
 *   addValidator('name', { test: (value) => boolean | string, ... })
 */
function normalizeValidator(name, spec) {
  if (spec instanceof RegExp) {
    spec = { pattern: spec };
  }
  if (typeof spec === 'function') {
    spec = { test: spec };
  }
  if (!spec || typeof spec !== 'object') {
    throw new TypeError(
      `addValidator("${name}"): expected a RegExp, a function, or a config object.`
    );
  }

  const patterns = spec.patterns || (spec.pattern ? [spec.pattern] : []);
  const hasTest = typeof spec.test === 'function';

  if (patterns.length === 0 && !hasTest) {
    throw new TypeError(
      `addValidator("${name}"): must include "pattern", "patterns", or "test".`
    );
  }

  const severity = spec.severity || 'medium';
  if (!SEVERITY_RANK[severity]) {
    throw new TypeError(
      `addValidator("${name}"): invalid severity "${severity}" (use low|medium|high).`
    );
  }

  let message = spec.message || { en: `Pattern "${name}" matched.`, es: `Patrón "${name}" detectado.` };
  if (typeof message === 'string') {
    message = { en: message, es: message };
  }

  return {
    type: spec.type || name,
    name,
    severity,
    message,
    patterns,
    test: hasTest ? spec.test : null,
    custom: true
  };
}

class Scanner {
  /**
   * @param {object} [options]
   * @param {'en'|'es'} [options.lang='en']   Message language.
   * @param {string[]}  [options.categories]  Limit built-in detectors to these types.
   * @param {'low'|'medium'|'high'} [options.minSeverity='low'] Minimum reported severity.
   */
  constructor(options = {}) {
    this.lang = options.lang === 'es' ? 'es' : 'en';
    this.minSeverity = options.minSeverity || 'low';
    this.customValidators = new Map();

    const categories = options.categories;
    this.detectors = Array.isArray(categories)
      ? builtInDetectors.filter((d) => categories.includes(d.type))
      : builtInDetectors;
  }

  /**
   * Register a custom sub-function / validator.
   * @returns {Scanner} this (chainable)
   */
  addValidator(name, spec) {
    if (typeof name !== 'string' || !name.trim()) {
      throw new TypeError('addValidator: name must be a non-empty string.');
    }
    this.customValidators.set(name, normalizeValidator(name, spec));
    return this;
  }

  /** Remove a custom validator. */
  removeValidator(name) {
    return this.customValidators.delete(name);
  }

  /** List custom validator names. */
  listValidators() {
    return [...this.customValidators.keys()];
  }

  _runDetector(detector, value) {
    let match = null;

    if (detector.patterns && detector.patterns.length) {
      match = firstMatch(value, detector.patterns);
    }
    if (!match && typeof detector.test === 'function') {
      const result = detector.test(value);
      if (result) {
        match = typeof result === 'string' ? result : value;
      }
    }
    if (!match) {
      return null;
    }

    return {
      type: detector.type,
      severity: detector.severity,
      message: detector.message[this.lang] || detector.message.en,
      match
    };
  }

  /**
   * Scan a value and return the details of any threats found.
   * @param {*} value
   * @param {object} [opts]
   * @param {'user'|'external'} [opts.source='user'] Set to 'external' when
   *   `value` comes from content the model reads but did not originate from
   *   the direct user (a document, email, web page, tool result...). Only
   *   then is the `indirect-injection` category evaluated — see Requirement
   *   3.5: without this explicit marker the library cannot tell "the user is
   *   instructing the assistant" (expected) from "third-party content is
   *   instructing the assistant" (suspicious).
   * @returns {{ safe: boolean, value: any, threats: Array }}
   */
  scan(value, opts = {}) {
    // Non-string values cannot carry a prompt injection payload.
    if (typeof value !== 'string') {
      return { safe: true, value, threats: [] };
    }

    const source = opts.source === 'external' ? 'external' : 'user';
    const minRank = SEVERITY_RANK[this.minSeverity] || 1;
    const threats = [];
    const allDetectors = [...this.detectors, ...this.customValidators.values()].filter(
      (detector) => detector.type !== 'indirect-injection' || source === 'external'
    );

    // Homoglyphs/compatibility forms don't hide anything (they just look
    // identical to their Latin counterpart), so they are folded BEFORE
    // matching — the underlying category is reported as-is (Requirement 8.3).
    const normalized = normalize(value);

    for (const detector of allDetectors) {
      if (SEVERITY_RANK[detector.severity] < minRank) {
        continue;
      }
      const threat = this._runDetector(detector, normalized);
      if (threat) {
        threats.push(threat);
      }
    }

    // Requirement 8: payload extraction. Base64/hex/ROT13/Unicode-tag-char
    // variants are decoded and re-checked against the same detectors, but
    // any match here is reported as its own 'encoded-payload' category
    // (never the underlying one) since the attacker had to hide it.
    let sawHiddenCharsThreat = false;
    for (const variant of decodeVariants(value)) {
      for (const detector of allDetectors) {
        const hit = this._runDetector(detector, variant.decoded);
        if (!hit) {
          continue;
        }
        const severity = maxSeverity('medium', hit.severity);
        if (SEVERITY_RANK[severity] < minRank) {
          continue;
        }
        if (variant.match === HIDDEN_CHARS_MATCH) {
          sawHiddenCharsThreat = true;
        }
        threats.push({
          type: 'encoded-payload',
          severity,
          message:
            this.lang === 'es'
              ? `Posible payload ofuscado (${variant.encoding}) que decodifica a un patrón de "${hit.type}".`
              : `Possible obfuscated payload (${variant.encoding}) decoding to a "${hit.type}" pattern.`,
          match: variant.match
        });
      }
    }

    // Requirement 8.2: invisible/hidden Unicode characters are suspicious on
    // their own, even when the hidden text doesn't match a known category.
    if (hasInvisibleChars(value) && !sawHiddenCharsThreat && SEVERITY_RANK.medium >= minRank) {
      threats.push({
        type: 'encoded-payload',
        severity: 'medium',
        message:
          this.lang === 'es'
            ? 'Se detectaron caracteres Unicode invisibles/ocultos en el texto (posible mensaje oculto).'
            : 'Detected invisible/hidden Unicode characters in the text (possible hidden message).',
        match: HIDDEN_CHARS_MATCH
      });
    }

    // Deduplicate (a variant/detector pair can repeat across categories) and
    // sort by severity, highest first.
    const seen = new Set();
    const deduped = threats.filter((t) => {
      const key = `${t.type}::${t.match}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
    deduped.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);

    return { safe: deduped.length === 0, value, threats: deduped };
  }

  /** true if the value is safe. */
  isSafe(value, opts) {
    return this.scan(value, opts).safe;
  }

  /** true if ANY prompt injection threat is detected. */
  hasPromptInjection(value, opts) {
    return !this.isSafe(value, opts);
  }
}

module.exports = { Scanner, normalizeValidator };
