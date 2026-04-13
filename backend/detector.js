// =============================================================================
// detector.js — Core detection engine for Chat Shield
// Combines: rule-based patterns + TF-IDF keyword scoring + encoding detection
// =============================================================================

// ─── 1. RULE-BASED PATTERNS ──────────────────────────────────────────────────
// These are known adversarial phrases used in jailbreaks and prompt injections.
// Each pattern has a weight (0–1) indicating how dangerous it is.

const ADVERSARIAL_PATTERNS = [
  // Instruction override attacks
  { pattern: /ignore\s+(any|all)?\s*(previous|prior|above|earlier)?\s*(safety\s*)?(instructions?|rules?|guidelines?)/i, label: "Instruction override", weight: 0.95 },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, label: "Instruction override", weight: 0.95 },
  { pattern: /forget\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i, label: "Instruction override", weight: 0.90 },
  { pattern: /override\s+(your\s+)?(previous\s+)?(instructions?|rules?|guidelines?|system)/i, label: "Instruction override", weight: 0.90 },
  
  // Persona/role hijacking
  { pattern: /you\s+are\s+now\s+(DAN|an?\s+AI|a\s+language\s+model|unrestricted)/i, label: "Persona hijack", weight: 0.92 },
  { pattern: /act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(DAN|evil|unrestricted|jailbroken)/i, label: "Persona hijack", weight: 0.88 },
  { pattern: /pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(DAN|evil|unrestricted|jailbroken|an?\s+AI\s+without)/i, label: "Persona hijack", weight: 0.88 },
  { pattern: /\bDAN\b/i, label: "DAN jailbreak", weight: 0.85 },
  { pattern: /jailbreak/i, label: "Jailbreak keyword", weight: 0.80 },
  
  // System prompt extraction
  { pattern: /repeat\s+(the\s+)?(above|your\s+system|all\s+previous)\s+(prompt|instructions?|text)/i, label: "Prompt extraction", weight: 0.85 },
  { pattern: /what\s+(are|were)\s+your\s+(initial\s+)?(instructions?|system\s+prompt|guidelines?)/i, label: "Prompt extraction", weight: 0.75 },
  { pattern: /reveal\s+(your\s+)?(system\s+prompt|instructions?|training)/i, label: "Prompt extraction", weight: 0.85 },
  { pattern: /print\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt)/i, label: "Prompt extraction", weight: 0.82 },
  
  // Restriction bypass
  { pattern: /without\s+(any\s+)?(restrictions?|filters?|limitations?|censorship|guardrails?)/i, label: "Restriction bypass", weight: 0.85 },
  { pattern: /bypass\s+(your\s+)?(safety|security|content|restrictions?|filters?)/i, label: "Restriction bypass", weight: 0.90 },
  { pattern: /disable\s+(your\s+)?(safety|content|ethical|moral)\s+(filter|mode|guidelines?)/i, label: "Restriction bypass", weight: 0.88 },
  
  // Harmful content requests
  { pattern: /how\s+to\s+(make|create|build|synthesize)\s+(a\s+)?(bomb|weapon|poison|malware|virus)/i, label: "Harmful content request", weight: 0.98 },
  { pattern: /step.by.step\s+(guide|instructions?)\s+(for\s+)?(hacking|attacking|exploiting)/i, label: "Harmful content request", weight: 0.92 },
  
  // Token smuggling / special chars
  { pattern: /[\u200b\u200c\u200d\u2060\ufeff]/g, label: "Hidden Unicode characters", weight: 0.80 },
  
  // Prompt delimiter injection
  { pattern: /(###|---|\*\*\*|===)\s*(system|user|assistant|human|ai)\s*(\n|:)/i, label: "Delimiter injection", weight: 0.85 },
  { pattern: /<\|?(im_start|im_end|endoftext|system|user|assistant)\|?>/i, label: "Delimiter injection", weight: 0.90 },
  
  // Role/mode switching
  { pattern: /enter\s+(developer|sudo|god|admin|unrestricted)\s+mode/i, label: "Mode switching", weight: 0.88 },
  { pattern: /switch\s+to\s+(developer|sudo|god|admin|unrestricted|evil)\s+mode/i, label: "Mode switching", weight: 0.88 },

  // NEW — critical patterns
  { pattern: /from\s+now\s+on.*(ignore|bypass|not\s+follow|disregard)/i, label: "Instruction override", weight: 0.88 },

  { pattern: /(no|without|free\s+from)\s+(any\s+)?(restrictions?|rules?|filters?)/i, label: "Restriction bypass", weight: 0.90 },

  { pattern: /(respond|answer)\s+(freely|without\s+filters|without\s+restriction)/i, label: "Restriction bypass", weight: 0.85 },

  { pattern: /from\s+now\s+on/i, label: "Instruction override", weight: 0.85 },

  { pattern: /(no|without)\s+(any\s+)?(restrictions?|rules?|filters?)/i, label: "Restriction bypass", weight: 0.90 },

  { pattern: /(respond|answer)\s+(freely|without\s+filters)/i, label: "Restriction bypass", weight: 0.85 },
];

// ─── 2. SUSPICIOUS PATTERNS (lower severity) ──────────────────────────────────
const SUSPICIOUS_PATTERNS = [
  { pattern: /act\s+as\s+(a|an)\s+/i, label: "Role-play request", weight: 0.50 },
  { pattern: /imagine\s+you\s+(are|were|have\s+no)/i, label: "Hypothetical framing", weight: 0.80 },
  { pattern: /for\s+(educational|research|academic|fictional|hypothetical)\s+purposes?/i, label: "Purpose disclaimer", weight: 0.70 },
  { pattern: /in\s+a\s+(fictional|hypothetical|story|roleplay)\s+scenario/i, label: "Fictional framing", weight: 0.75 },
  { pattern: /what\s+would\s+(happen|you\s+say|you\s+do)\s+if\s+you\s+(had\s+no|were\s+not|didn'?t\s+have)/i, label: "Constraint removal", weight: 0.65 },
  { pattern: /my\s+(grandmother|grandpa|teacher)\s+(used\s+to|would)\s+tell\s+me/i, label: "Social engineering", weight: 0.70 },
  { pattern: /\[?(system|admin|root|sudo)\]?\s*:/i, label: "Privilege escalation", weight: 0.85 },
  { pattern: /token\s+(limit|budget|count)/i, label: "Token manipulation", weight: 0.80 },
];

// ─── 3. ENCODING DETECTION ─────────────────────────────────────────────────────
// Detects obfuscated content that might hide adversarial instructions

function detectEncoding(text) {
  const flags = [];

  // Base64 detection — matches long base64-encoded strings
  const base64Regex = /(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const base64Matches = text.match(base64Regex) || [];
  if (base64Matches.length > 0) {
    // Try to decode and check if it produces readable text (possible hidden instruction)
    for (const match of base64Matches) {
      try {
        const decoded = Buffer.from(match, "base64").toString("utf8");
        // If decoded text has printable characters, flag it
        if (/[\x20-\x7E]{5,}/.test(decoded)) {
          flags.push({ label: "Base64 encoded content", match, decoded: decoded.slice(0, 50), weight: 0.75 });
        }
      } catch (_) {}
    }
  }

  // Leetspeak / character substitution detection
  const leetRegex = /[1!|][gG][n|N][o0O][r|R][e3][^\s]{0,10}/; // "1gn0r3" style
  if (leetRegex.test(text)) {
    flags.push({ label: "Leetspeak obfuscation", weight: 0.75 });
  }

  // Abnormal whitespace / zero-width space injection
  if (/[\u200b-\u200d\u2060\ufeff]/.test(text)) {
    flags.push({ label: "Hidden Unicode zero-width characters", weight: 0.80 });
  }

  // Excessive punctuation or spacing between letters (e.g., "i g n o r e")
  if (/(\b\w\s){4,}\w\b/.test(text)) {
    flags.push({ label: "Spaced-out text (obfuscation)", weight: 0.80 });
  }

  // Hex encoding detection
  if (/\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}/i.test(text)) {
    flags.push({ label: "Hex-encoded content", weight: 0.72 });
  }

  // ROT13 / Caesar cipher hints (common words appear garbled)
  if (/\b(vta|vgab|tano|cnff|frperg)\b/i.test(text)) {
    flags.push({ label: "Possible ROT13 obfuscation", weight: 0.75 });
  }

  return flags;
}

// ─── 4. TF-IDF KEYWORD SCORER ─────────────────────────────────────────────────
// Lightweight keyword frequency scoring without needing scikit-learn.
// Maps high-risk words to weights and scores the prompt.

const HIGH_RISK_KEYWORDS = {
  // Jailbreak vocab
  "jailbreak": 0.90, "dan": 0.85, "unrestricted": 0.80, "uncensored": 0.78,
  "unfiltered": 0.75, "bypass": 0.82, "override": 0.80, "disable": 0.70,
  "ignore": 0.85, "forget": 0.80, "disregard": 0.70, "pretend": 0.75,
  // Harmful content
  "bomb": 0.90, "weapon": 0.85, "malware": 0.88, "exploit": 0.75,
  "hack": 0.75, "inject": 0.70, "poison": 0.80, "attack": 0.65,
  // Manipulation
  "grandma": 0.50, "fictional": 0.85, "hypothetical": 0.70, "roleplay": 0.80,
  "persona": 0.75, "simulate": 0.80, "impersonate": 0.775,
  // Privilege
  "sudo": 0.70, "admin": 0.75, "root": 0.65, "developer mode": 0.80,
  "god mode": 0.82, "system prompt": 0.75, "you are a developer":0.80,
};

function keywordScore(text) {
  const words = text.toLowerCase().split(/\s+/);
  let totalScore = 0;
  const matchedKeywords = [];

  for (const [keyword, weight] of Object.entries(HIGH_RISK_KEYWORDS)) {
    // Multi-word keywords
    if (keyword.includes(" ")) {
      if (text.toLowerCase().includes(keyword)) {
        totalScore += weight;
        matchedKeywords.push({ keyword, weight });
      }
    } else {
      if (words.includes(keyword)) {
        totalScore += weight;
        matchedKeywords.push({ keyword, weight });
      }
    }
  }

  // Normalize to 0–1 range (cap at 1)
  const normalizedScore = Math.min(totalScore / 3, 1);
  return { score: normalizedScore, matched: matchedKeywords };
}

// ─── 5. MAIN ANALYSIS FUNCTION ────────────────────────────────────────────────

function analyzePrompt(text) {
  if (!text || text.trim().length === 0) {
    return {
      classification: "SAFE",
      confidence: 0,
      reasons: [],
      highlights: [],
      scores: { semantic: 0, keyword: 0, encoding: 0 },
    };
  }

  const reasons = [];
  const highlights = []; // { start, end, label, severity }

  // --- Run rule-based adversarial detection ---
  let maxAdversarialWeight = 0;
  for (const { pattern, label, weight } of ADVERSARIAL_PATTERNS) {
    // Reset regex state
    const re = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = re.exec(text)) !== null) {
      if (!reasons.find(r => r.label === label)) {
        reasons.push({ label, weight, severity: "adversarial" });
      }
      highlights.push({
        start: match.index,
        end: match.index + match[0].length,
        label,
        severity: "adversarial",
        text: match[0],
      });
      maxAdversarialWeight = Math.max(maxAdversarialWeight, weight);
      // Prevent infinite loop on zero-width matches
      if (match.index === re.lastIndex) re.lastIndex++;
    }
  }

  // --- Run suspicious pattern detection ---
  let maxSuspiciousWeight = 0;
  for (const { pattern, label, weight } of SUSPICIOUS_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = re.exec(text)) !== null) {
      if (!reasons.find(r => r.label === label)) {
        reasons.push({ label, weight, severity: "suspicious" });
      }
      highlights.push({
        start: match.index,
        end: match.index + match[0].length,
        label,
        severity: "suspicious",
        text: match[0],
      });
      maxSuspiciousWeight = Math.max(maxSuspiciousWeight, weight);
      if (match.index === re.lastIndex) re.lastIndex++;
    }
  }

  // --- Encoding detection ---
  const encodingFlags = detectEncoding(text);
  let encodingScore = 0;
  for (const flag of encodingFlags) {
    reasons.push({ label: flag.label, weight: flag.weight, severity: "encoding" });
    encodingScore = Math.max(encodingScore, flag.weight);
    // Highlight base64 matches in the text
    if (flag.match) {
      const idx = text.indexOf(flag.match);
      if (idx !== -1) {
        highlights.push({
          start: idx,
          end: idx + flag.match.length,
          label: flag.label,
          severity: "encoding",
          text: flag.match,
        });
      }
    }
  }

  // --- Keyword scoring (semantic/TF-IDF proxy) ---
  const { score: keywordScoreVal, matched: matchedKeywords } = keywordScore(text);

  // ─── 6. COMBINE SCORES ───────────────────────────────────────────────────────
  // Weighted combination:
  // - Rule-based patterns (most reliable)  → 50%
  // - Keyword/semantic score               → 30%
  // - Encoding detection                   → 20%

  let ruleScore = 0;

  // combine adversarial signals
  if (maxAdversarialWeight > 0) {
    ruleScore += maxAdversarialWeight;
  }

  // combine suspicious signals
  if (maxSuspiciousWeight > 0) {
    ruleScore += maxSuspiciousWeight * 0.5;
  }

  ruleScore = Math.min(ruleScore, 1);
  const finalScore =
    ruleScore * 0.50 +
    keywordScoreVal * 0.30 +
    encodingScore * 0.20;

  const confidence = Math.min(finalScore, 1);

  // 🔥 HARD OVERRIDE (ADD HERE)
  if (maxAdversarialWeight >= 0.85) {
    return {
      classification: "ADVERSARIAL",
      confidence: 0.9,
      reasons,
      highlights,
      scores: {
        semantic: parseFloat(keywordScoreVal.toFixed(3)),
        keyword: parseFloat(Math.max(maxAdversarialWeight, maxSuspiciousWeight).toFixed(3)),
        encoding: parseFloat(encodingScore.toFixed(3)),
      },
      matchedKeywords,
    };
  }

  // ─── 7. CLASSIFY ─────────────────────────────────────────────────────────────
  let classification;
  if (maxAdversarialWeight >= 0.75 || confidence >= 0.65) {
    classification = "ADVERSARIAL";
  } else if (confidence >= 0.30 || maxSuspiciousWeight >= 0.40 || encodingScore >= 0.55) {
    classification = "SUSPICIOUS";
  } else {
    classification = "SAFE";
  }

  // ─── 8. BUILD SCORE BREAKDOWN ────────────────────────────────────────────────
  const scores = {
    semantic: parseFloat(keywordScoreVal.toFixed(3)),
    keyword: parseFloat(Math.max(maxAdversarialWeight, maxSuspiciousWeight).toFixed(3)),
    encoding: parseFloat(encodingScore.toFixed(3)),
  };

  return {
    classification,
    confidence: parseFloat(confidence.toFixed(3)),
    reasons: reasons.sort((a, b) => b.weight - a.weight), // sort by severity
    highlights,
    scores,
    matchedKeywords,
  };
}

// ─── 9. SAFE PROMPT REWRITER ──────────────────────────────────────────────────
// Rewrites adversarial prompts into safer versions by:
// 1. Stripping known adversarial phrases
// 2. Replacing them with neutral equivalents

function rewritePrompt(text) {
  let safe = text;

  const replacements = [
    [/ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/gi, ""],
    [/disregard\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/gi, ""],
    [/forget\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/gi, ""],
    [/you\s+are\s+now\s+DAN/gi, "you are an AI assistant"],
    [/act\s+as\s+(if\s+you\s+are\s+)?DAN/gi, ""],
    [/without\s+(any\s+)?(restrictions?|filters?|limitations?|censorship)/gi, "appropriately"],
    [/bypass\s+(your\s+)?(safety|security|content)\s+(filter|guidelines?)?/gi, ""],
    [/jailbreak(ed)?/gi, ""],
    [/\bDAN\b/gi, ""],
    [/enter\s+(developer|sudo|god|admin)\s+mode/gi, ""],
  ];

  for (const [pattern, replacement] of replacements) {
    safe = safe.replace(pattern, replacement);
  }

  // Clean up multiple spaces and trim
  safe = safe.replace(/\s{2,}/g, " ").trim();

  // If the rewritten text is very short (we stripped most of it), add context
  if (safe.length < 20 && text.length > 50) {
    safe = "Please help me with: " + safe;
  }

  return safe || "Please help me with a question.";
}

module.exports = { analyzePrompt, rewritePrompt };
