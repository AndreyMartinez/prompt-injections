# Changelog

All notable changes to this project are documented here.

This project adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-11-11

### Changed
- README: new 11-category threat illustration, colored code example image and
  updated evasion notes. No code changes.

## [0.2.0] - 2026-11-10

Update driven by newly reported prompt injection techniques against AI agents
(MCP tool poisoning, promptware C2, persistent memory/config injection, hidden
content and Unicode smuggling).

### Added
- `tool-poisoning` category: secret-file read + send instructions in tool
  descriptions, "before using this tool..." lures, cross-server shadowing.
- `concealment` category: "do not tell the user" / "without informing the
  user" (en/es).
- `persistence` category: instructions planted for future sessions or in
  `AGENTS.md`, `CLAUDE.md`, `.cursorrules` and similar files.
- `c2-promptware` category: agent told to fetch and obey remote instructions.
- `hidden-content` category: instruction-bearing HTML comments, invisible CSS
  text and ANSI terminal escape sequences.
- `fake-delimiter`: `<system>`, `<IMPORTANT>`, `<<SYS>>`, `[INST]`, and extra
  chat-template tokens (`<|endoftext|>`, `<|eot_id|>`, ...).
- `indirect-injection`: "note to the assistant" and fake orchestrator messages.
- `data-exfiltration`: more auto-loaded-URL parameters and DNS/subdomain exfil.
- `encoded-payload`: bidi control characters and variation-selector smuggling
  (decoded and re-scanned).

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
