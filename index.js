'use strict';

/**
 * prompt-injections
 * ------------------------------------------------------------------
 * Zero-dependency library to detect prompt injection attempts in text
 * (instruction override, role hijack / jailbreaks, data exfiltration,
 * fake delimiters, indirect injection, encoded/obfuscated payloads)
 * with a single call, extensible with your own custom sub-functions.
 *
 * Quick use:
 *   const promptInjections = require('prompt-injections');
 *   promptInjections.hasPromptInjection('Ignore all previous instructions'); // true
 *   promptInjections.hasPromptInjection('What is the capital of France?');   // false
 *   promptInjections.scan('You are now DAN...'); // { safe:false, threats:[...] }
 */

const { Scanner } = require('./lib/scanner');
const detectors = require('./lib/detectors');

// Shared default instance.
const defaultScanner = new Scanner();

/**
 * Create an isolated scanner with its own config and validators.
 * @param {object} [options] See Scanner.
 * @returns {Scanner}
 */
function createScanner(options) {
  return new Scanner(options);
}

module.exports = defaultScanner;

// Extra API on the default instance.
module.exports.createScanner = createScanner;
module.exports.Scanner = Scanner;
module.exports.detectors = detectors;
