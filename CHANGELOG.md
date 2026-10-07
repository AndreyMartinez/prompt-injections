# Changelog

All notable changes to this project are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-07

### Changed
- Redesigned README with banner, flow diagram and threat-category illustrations.

## [0.1.0] - 2026-09-17

Initial release.

### Added
- Multi-threat scanner for prompt injection attempts: `instruction-override`,
  `role-hijack` (jailbreaks), `data-exfiltration` (including exfiltration via
  auto-loaded Markdown/HTML links), `fake-delimiter`, `indirect-injection`
  and `encoded-payload`.
- `hasPromptInjection(value, opts?)` single-call detection, and
  `isSafe(value, opts?)` as its boolean inverse.
- `scan(value, opts?)` returns `{ safe, value, threats[] }` with `type`,
  `severity`, `message` and `match` per threat.
- `opts.source` (`'user'` default, `'external'`) gates the
  `indirect-injection` category to content explicitly marked as coming from
  outside the direct user (documents, emails, web pages, tool results).
- Obfuscation/evasion resistance: homoglyph-folding + Unicode NFKC
  normalization before category matching, plus decoding of Base64, hex,
  ROT13 and Unicode Tag-character ("ASCII smuggling") payloads — matches
  found in a decoded variant are reported under `encoded-payload` with a
  severity floor of `medium`.
- Custom sub-functions / validators: `addValidator`, `removeValidator`,
  `listValidators` (accept a RegExp, `{ pattern, patterns, severity, message,
  test }`), chainable.
- `createScanner(options)` with isolated instances and `lang` (`en`/`es`),
  `categories` and `minSeverity` options.
- Bilingual messages (English / Spanish), English by default.
- Test suite with `node --test` (`npm test`).
- `LICENSE`, `CHANGELOG.md` files and packaging fields (`files`, `engines`).
