'use strict';

/**
 * Built-in detectors for prompt injection attack categories.
 *
 * Each detector:
 *   type:      category id
 *   severity:  'low' | 'medium' | 'high'
 *   message:   { en, es } human-readable description
 *   patterns:  RegExp[] — attack *syntax*, NOT bare words
 *              (matching real syntax keeps false positives low)
 */

const detectors = [
  {
    type: 'instruction-override',
    severity: 'high',
    message: {
      en: 'Possible attempt to override or ignore prior instructions/system prompt.',
      es: 'Posible intento de anular o ignorar instrucciones previas / system prompt.'
    },
    patterns: [
      /\b(ignore|disregard|forget|override)\b[\s\S]{0,40}\b(?:(?:previous|prior|above|earlier|all)\s+)?(instructions?|rules?|prompt|directives?)\b/i,
      /\b(ignora|desestima|olvida|omite)\b[\s\S]{0,40}\b(las?\s+instrucciones|reglas|prompt)\b[\s\S]{0,30}\b(anteriores?|previas?|de\s+arriba)\b/i,
      /\bnew\s+instructions?\s*:/i,
      /\bfrom\s+now\s+on\b[\s\S]{0,30}\byou\s+(will|must|shall)\b/i
    ]
  },
  {
    type: 'role-hijack',
    severity: 'high',
    message: {
      en: 'Possible jailbreak / unauthorized role or persona change.',
      es: 'Posible jailbreak / cambio de rol o persona no autorizado.'
    },
    patterns: [
      /\byou\s+are\s+now\b[\s\S]{0,30}\b(dan|an?\s+ai\s+with\s+no|unfiltered|uncensored|jailbroken?)\b/i,
      /\bact\s+as\b[\s\S]{0,30}\b(an?\s+ai\s+with\s+no\s+restrictions|unfiltered|uncensored|dan|jailbroken?)\b/i,
      /\b(pretend|imagine)\s+(you\s+are|to\s+be)\b[\s\S]{0,30}\b(an?\s+(ai|assistant)\s+with\s+no|unrestricted|no\s+rules)\b/i,
      /\bact[uú]a\s+como\b[\s\S]{0,30}\b(una?\s+ia\s+sin\s+(restricciones|filtros|reglas)|sin\s+filtros|sin\s+reglas)\b/i,
      /\bahora\s+eres\b[\s\S]{0,30}\b(una?\s+ia\s+sin|sin\s+filtros|sin\s+reglas)\b/i
    ]
  },
  {
    type: 'data-exfiltration',
    severity: 'high',
    message: {
      en: 'Possible attempt to exfiltrate the system prompt, hidden instructions or context data (including via auto-loaded links).',
      es: 'Posible intento de exfiltrar el system prompt, instrucciones ocultas o datos de contexto (incluida la vía de enlaces auto-cargables).'
    },
    patterns: [
      /\b(repeat|print|reveal|show|output)\b[\s\S]{0,20}\b(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+instructions)\b/i,
      /\b(repite|revela|muestra|imprime)\b[\s\S]{0,20}\b(tu\s+)?(system\s+prompt|instrucciones\s+(del\s+sistema|iniciales|ocultas))\b/i,
      /\b(system\s+prompt|instructions)\b[\s\S]{0,20}\bverbatim\b/i,
      // Markdown/HTML auto-loaded resource whose URL carries context/secret data.
      /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?[^\s)]*\b(data|secret|token|prompt|leak|key)\s*=[^\s)]*\)/i,
      /<img[^>]+src\s*=\s*["']https?:\/\/[^"']*\?[^"']*\b(data|secret|token|prompt|leak|key)\s*=/i
    ]
  },
  {
    type: 'fake-delimiter',
    severity: 'medium',
    message: {
      en: 'Possible fake system/role delimiter simulating a privileged message.',
      es: 'Posible delimitador falso de sistema/rol que simula un mensaje privilegiado.'
    },
    patterns: [
      /\[\s*system\s*\]/i,
      /<\|\s*(system|assistant|im_start|im_end)\s*\|>/i,
      /###\s*(system\s+)?instruction\s*:/i,
      /\[\s*\/?\s*(assistant|user)\s*\]\s*[:\-]/i
    ]
  },
  {
    type: 'indirect-injection',
    severity: 'medium',
    message: {
      en: 'Possible indirect injection: instructions explicitly addressed at an AI/assistant reader.',
      es: 'Posible inyección indirecta: instrucciones dirigidas explícitamente a un lector IA/asistente.'
    },
    patterns: [
      /\battention\s+ai\b/i,
      /\bdear\s+ai\b/i,
      /\bif\s+you\s+are\s+an?\s+(ai|language\s+model|llm)\s+reading\s+this\b/i,
      /\bwhen\s+you\s+(read|process|summarize)\s+this\s+(document|page|email|content)\b[\s\S]{0,40}\b(forward|ignore|first|must|always)\b/i,
      /\bnota\s+a\s+la\s+ia\b/i,
      /\bsi\s+eres\s+una?\s+ia\s+leyendo\s+esto\b/i
    ]
  }
];

module.exports = detectors;
