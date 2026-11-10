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
      /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]*\?[^\s)]*\b(data|secret|token|prompt|leak|key|payload|context|auth|password|session|cookie|d)\s*=[^\s)]*\)/i,
      /<img[^>]+src\s*=\s*["']https?:\/\/[^"']*\?[^"']*\b(data|secret|token|prompt|leak|key|payload|context|auth|password|session|cookie|d)\s*=/i,
      // DNS / subdomain exfiltration of secrets.
      /\b(secrets?|credentials?|tokens?|keys?|contents?)\b[\s\S]{0,60}\b(as|in|into)\s+(an?\s+|the\s+)?(subdomain|dns\s+(lookup|query|request)|url\s+(parameter|query))\b/i
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
      /<\|\s*(system|assistant|user|im_start|im_end|endoftext|eot_id|start_header_id|end_header_id)\s*\|>/i,
      /<<\s*\/?sys\s*>>|\[\s*\/?inst\s*\]/i,
      /<\s*\/?\s*(system|important)\s*>/i,
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
      /\b(note|message|instructions?)\s+(to|for)\s+the\s+(ai\s+)?(assistant|agent|model|llm)\b/i,
      /\b(task\s+update|message)\s+from\s+(the\s+)?(orchestrator|supervisor|planner)\b/i,
      /\bnota\s+a\s+la\s+ia\b/i,
      /\bsi\s+eres\s+una?\s+ia\s+leyendo\s+esto\b/i
    ]
  },
  {
    type: 'tool-poisoning',
    severity: 'high',
    message: {
      en: 'Possible tool/MCP poisoning: tool metadata or output instructing the agent to read secrets, leak data or intercept other tools.',
      es: 'Posible envenenamiento de herramientas/MCP: metadatos o salida de una herramienta que ordena al agente leer secretos, filtrar datos o interceptar otras herramientas.'
    },
    patterns: [
      // Sensitive file + send/include verb (either order).
      /(~\/\.ssh|\.ssh\/id_\w+|\bid_rsa\b|\.aws\/credentials|\.npmrc|\.git-credentials|\/etc\/passwd|(?:^|[\s\/'"])\.env\b)[\s\S]{0,120}\b(send|post|upload|include|append|forward|exfiltrate|curl|pass|attach)\b/i,
      /\b(send|post|upload|include|append|forward|exfiltrate|curl|pass|attach)\b[\s\S]{0,120}(~\/\.ssh|\.ssh\/id_\w+|\bid_rsa\b|\.aws\/credentials|\.npmrc|\.git-credentials|\/etc\/passwd|(?:^|[\s\/'"])\.env\b)/i,
      /\bbefore\s+(using|calling|running|invoking)\s+this\s+tool\b[\s,:]*(you\s+must\s+)?(first\s+)?(send|include|append|forward|upload)\b/i,
      // Cross-server shadowing / interception.
      /\b(instead\s+of|rather\s+than|do\s+not\s+use)\b[\s\S]{0,30}\b(the\s+)?(other|original|trusted|official)\s+\w*\s*tool\b/i,
      /\b(whenever|every\s+time|each\s+time)\b[\s\S]{0,40}\b(send|forward|bcc|cc)\b[\s\S]{0,40}\b(e-?mails?|messages?)\b[\s\S]{0,30}\bto\b[\s\S]{0,40}@/i
    ]
  },
  {
    type: 'concealment',
    severity: 'medium',
    message: {
      en: 'Possible instruction to hide actions or the injected note from the user.',
      es: 'Posible instrucción para ocultar acciones o la nota inyectada al usuario.'
    },
    patterns: [
      /\b(do\s+not|don'?t|never)\s+(tell|inform|mention|notify|alert|disclose)\b[\s\S]{0,25}\b(this\s+(note|message|instruction)s?|the\s+user|user)\b/i,
      /\bwithout\s+(telling|informing|notifying|alerting)\s+the\s+user\b/i,
      /\b(do\s+not|don'?t|never)\s+mention\s+this\b/i,
      /\bno\s+(le\s+)?(digas|menciones|informes|avises)\b[\s\S]{0,25}\b(al\s+usuario|esta\s+nota)\b/i,
      /\bsin\s+(avisar|informar|decir)(le)?\s+al\s+usuario\b/i
    ]
  },
  {
    type: 'persistence',
    severity: 'medium',
    message: {
      en: 'Possible persistent injection: attempt to plant instructions in agent memory or config files for future sessions.',
      es: 'Posible inyección persistente: intento de plantar instrucciones en la memoria o archivos de configuración del agente para sesiones futuras.'
    },
    patterns: [
      /\b(remember|memorize|save|store)\b[\s\S]{0,40}\b(for\s+)?(all\s+|every\s+)?(future|later|next)\s+(sessions?|conversations?|chats?|interactions?)\b/i,
      /\b(always|every|ignore|must|never)\b[\s\S]{0,80}\b(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.cursor\/rules|copilot-instructions\.md)\b/i,
      /\b(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.cursor\/rules|copilot-instructions\.md)\b[\s\S]{0,80}\b(always|every|ignore|must|never)\b/i
    ]
  },
  {
    type: 'c2-promptware',
    severity: 'high',
    message: {
      en: 'Possible command-and-control promptware: agent told to repeatedly fetch and obey remote instructions.',
      es: 'Posible promptware de comando y control: se ordena al agente obtener y obedecer instrucciones remotas de forma repetida.'
    },
    patterns: [
      /\b(each|every)\s+(run|time|session|turn|cycle|hour|day)\b[\s\S]{0,60}\b(fetch|download|poll|check|retrieve|curl|visit|load)\b[\s\S]{0,60}https?:\/\/[\s\S]{0,80}\b(follow|execute|obey|run|apply|carry\s+out)\b/i,
      /\b(fetch|download|retrieve|poll)\b[\s\S]{0,60}https?:\/\/\S+[\s\S]{0,60}\b(execute|obey)\s+(the\s+|any\s+|all\s+)?(instructions?|commands?|tasks?|steps)\b/i
    ]
  },
  {
    type: 'hidden-content',
    severity: 'medium',
    message: {
      en: 'Possible hidden instructions (HTML comment, invisible CSS text or terminal escape sequences).',
      es: 'Posibles instrucciones ocultas (comentario HTML, texto CSS invisible o secuencias de escape de terminal).'
    },
    patterns: [
      /<!--[^>]{0,300}?\b(ignore|disregard|you\s+must|system\s+prompt|do\s+not\s+tell|(ai|assistant|agent|llm)\s*[:,])[^>]{0,300}?-->/i,
      /style\s*=\s*["'][^"']*(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)[^"']*["'][^>]*>[^<]{0,300}\b(ignore|assistant|ai\s+agent|you\s+must|instructions?)\b/i,
      /\x1b\[[0-9;?]*[ -\/]*[@-~]/
    ]
  }
];

module.exports = detectors;
