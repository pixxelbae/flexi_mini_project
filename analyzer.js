// Password strength analysis: entropy, weak-pattern detection, crack-time estimates.
// Works in the browser (loaded after wordlists.js) and in Node (for tests).

const WL = typeof module !== 'undefined'
  ? require('./wordlists.js')
  : { COMMON_PASSWORDS, DICTIONARY_WORDS };

const COMMON_RANK = new Map(WL.COMMON_PASSWORDS.map((p, i) => [p, i + 1]));
const WORDS = [...new Set([
  ...WL.DICTIONARY_WORDS,
  ...WL.COMMON_PASSWORDS.filter(p => /^[a-z]{4,}$/.test(p)),
])];

// An attacker's dictionary has ~100,000 words, so picking one word is worth ~17 bits.
const WORD_BITS = Math.log2(100000);
// A year between 1900 and 2049 is one of 150 choices (~7 bits).
const YEAR_BITS = Math.log2(150);

const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '1qaz2wsx3edc4rfv5tgb'];
const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i' };

const ATTACKS = [
  { name: 'Online attack, rate-limited', detail: 'Site locks out after a few tries: ~100 guesses/hour', rate: 100 / 3600 },
  { name: 'Online attack, no rate limit', detail: '~10 guesses/second', rate: 10 },
  { name: 'Offline attack, slow hash (bcrypt)', detail: 'Stolen database: ~10,000 guesses/second', rate: 1e4 },
  { name: 'Offline attack, fast hash (MD5) on a GPU', detail: 'Stolen database: ~100 billion guesses/second', rate: 1e11 },
];

const LEVELS = [
  { label: 'Very weak', minBits: 0 },
  { label: 'Weak', minBits: 28 },
  { label: 'Fair', minBits: 36 },
  { label: 'Strong', minBits: 60 },
  { label: 'Very strong', minBits: 80 },
];

// Size of the character set an attacker must search, based on which kinds of characters appear.
function charsetPool(pw) {
  const classes = [];
  if (/[a-z]/.test(pw)) classes.push({ name: 'lowercase', size: 26 });
  if (/[A-Z]/.test(pw)) classes.push({ name: 'uppercase', size: 26 });
  if (/[0-9]/.test(pw)) classes.push({ name: 'digits', size: 10 });
  if (/[\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]/.test(pw)) classes.push({ name: 'symbols', size: 33 });
  if (/[^\x00-\x7F]/.test(pw)) classes.push({ name: 'other (unicode)', size: 100 });
  return { classes, size: classes.reduce((sum, c) => sum + c.size, 0) };
}

// The lowercase password plus versions with leetspeak undone (p@ssw0rd -> password).
// Each substitution is one character for one character, so positions stay aligned.
function leetVariants(lower) {
  const undo = oneFor => [...lower].map(c => (c === '1' ? oneFor : LEET[c] || c)).join('');
  return [...new Set([lower, undo('i'), undo('l')])];
}

function findPatterns(pw, poolSize) {
  const lower = pw.toLowerCase();
  const variants = leetVariants(lower);
  const charBits = Math.log2(poolSize);
  const patterns = [];
  const add = (type, start, len, bits, message) =>
    patterns.push({ type, start, end: start + len, bits, text: pw.slice(start, start + len), message });

  // 1. The whole password is on the common-passwords list.
  for (const v of variants) {
    const rank = COMMON_RANK.get(v);
    if (rank) {
      const bits = Math.log2(rank) + (/[A-Z]/.test(pw) ? 1 : 0) + (v !== lower ? 1 : 0);
      add('common', 0, pw.length, bits, `Is #${rank} on the list of most common passwords`);
      break;
    }
  }

  // 2. Dictionary words anywhere inside (also catches leetspeak versions).
  for (const v of variants) {
    for (const w of WORDS) {
      for (let idx = v.indexOf(w); idx !== -1; idx = v.indexOf(w, idx + 1)) {
        const span = pw.slice(idx, idx + w.length);
        const leet = span.toLowerCase() !== w;
        const bits = WORD_BITS + (/[A-Z]/.test(span) ? 1 : 0) + (leet ? 1 : 0);
        add('dictionary', idx, w.length, bits,
          `Dictionary word "${w}"` + (leet ? ' (swapping letters for symbols does not fool crackers)' : ''));
      }
    }
  }

  // 3. Alphabetical or numerical sequences: abc, 1234, zyx, 9876.
  for (let i = 0; i < lower.length - 2;) {
    const step = lower.charCodeAt(i + 1) - lower.charCodeAt(i);
    let j = i + 1;
    while (Math.abs(step) === 1 && j + 1 < lower.length && lower.charCodeAt(j + 1) - lower.charCodeAt(j) === step) j++;
    const span = lower.slice(i, j + 1);
    if (Math.abs(step) === 1 && span.length >= 3 && /^([a-z]+|[0-9]+)$/.test(span)) {
      add('sequence', i, span.length, Math.log2(26) + Math.log2(span.length) + 1, `Sequence "${pw.slice(i, j + 1)}"`);
      i = j + 1;
    } else {
      i++;
    }
  }

  // 4. Keyboard walks: qwerty, asdf, 1qaz2wsx.
  const rows = [...KEYBOARD_ROWS, ...KEYBOARD_ROWS.map(r => [...r].reverse().join(''))];
  for (let i = 0; i < lower.length;) {
    let best = 0;
    for (const row of rows) {
      let len = 4;
      while (i + len <= lower.length && row.includes(lower.slice(i, i + len))) len++;
      best = Math.max(best, len - 1);
    }
    if (best >= 4) {
      add('keyboard', i, best, Math.log2(100) + Math.log2(best), `Keyboard pattern "${pw.slice(i, i + best)}"`);
      i += best;
    } else {
      i++;
    }
  }

  // 5. Repeated characters (aaaa) and repeated blocks (abcabc).
  for (const m of lower.matchAll(/(.)\1{2,}/g)) {
    add('repeat', m.index, m[0].length, charBits + Math.log2(m[0].length), `Repeated character "${pw.slice(m.index, m.index + m[0].length)}"`);
  }
  for (const m of lower.matchAll(/(.{2,}?)\1+/g)) {
    const count = m[0].length / m[1].length;
    add('repeat', m.index, m[0].length, m[1].length * charBits + Math.log2(count), `Repeated block "${pw.slice(m.index, m.index + m[0].length)}"`);
  }

  // 6. Years, a favourite of people and attackers alike.
  for (const m of pw.matchAll(/19\d\d|20[0-4]\d/g)) {
    add('year', m.index, 4, YEAR_BITS, `Year "${m[0]}"`);
  }

  return dedupe(patterns);
}

// Drop duplicates, and patterns that sit inside a bigger pattern that is already cheaper
// per character ("pass" inside "password"), since they would not change the score.
function dedupe(patterns) {
  const seen = new Set();
  const unique = patterns.filter(p => {
    const key = `${p.type}:${p.start}:${p.end}`;
    return !seen.has(key) && seen.add(key);
  });
  const perChar = p => p.bits / (p.end - p.start);
  return unique
    .filter(p => !unique.some(q => q !== p && q.start <= p.start && q.end >= p.end && perChar(q) <= perChar(p)))
    .sort((a, b) => a.start - b.start || b.end - a.end);
}

// Every character starts at log2(pool) bits. A pattern spreads its (much smaller) cost
// over the characters it covers, and each character keeps the cheapest cost that applies.
function effectiveBits(pw, poolSize, patterns) {
  const bits = new Array(pw.length).fill(Math.log2(poolSize));
  for (const p of patterns) {
    const perChar = p.bits / (p.end - p.start);
    for (let k = p.start; k < p.end; k++) bits[k] = Math.min(bits[k], perChar);
  }
  return bits.reduce((sum, b) => sum + b, 0);
}

function analyze(pw) {
  if (!pw) return null;

  const pool = charsetPool(pw);
  const naiveBits = pw.length * Math.log2(pool.size);
  const patterns = findPatterns(pw, pool.size);
  const bits = effectiveBits(pw, pool.size, patterns);

  let level = LEVELS.findLastIndex(l => bits >= l.minBits);
  if (pw.length < 8) level = Math.min(level, 1);

  // On average an attacker finds the password after searching half the possibilities.
  const guesses = 2 ** bits / 2;
  const crackTimes = ATTACKS.map(a => ({ ...a, seconds: guesses / a.rate }));

  const checks = [
    { label: 'At least 12 characters', ok: pw.length >= 12 },
    { label: 'Uppercase letter', ok: /[A-Z]/.test(pw) },
    { label: 'Lowercase letter', ok: /[a-z]/.test(pw) },
    { label: 'Number', ok: /[0-9]/.test(pw) },
    { label: 'Symbol', ok: /[^a-zA-Z0-9]/.test(pw) },
    { label: 'No common words or patterns', ok: patterns.length === 0 },
  ];

  return {
    length: pw.length, pool, naiveBits, bits, patterns, guesses, crackTimes, checks,
    level, label: LEVELS[level].label, suggestions: suggest(pw, patterns, checks),
  };
}

function suggest(pw, patterns, checks) {
  const types = new Set(patterns.map(p => p.type));
  const tips = [];
  if (types.has('common')) tips.push('This password is on public lists attackers try first. Never use it.');
  if (pw.length < 12) tips.push('Make it longer. Each extra character multiplies the work for an attacker.');
  if (types.has('dictionary')) tips.push('Avoid single dictionary words. A passphrase of 4+ random, unrelated words is stronger and easier to remember.');
  if (types.has('sequence') || types.has('keyboard')) tips.push('Avoid sequences and keyboard walks like abc, 123 or qwerty.');
  if (types.has('repeat')) tips.push('Avoid repeated characters or repeated chunks.');
  if (types.has('year')) tips.push('Avoid years and dates such as birthdays. They are among the first things attackers guess.');
  if (pw.length < 16 && checks.slice(1, 5).some(c => !c.ok)) tips.push('Mix in the missing character types (uppercase, numbers, symbols).');
  if (!tips.length) tips.push('Looks good. Use a password manager so every account gets its own unique password.');
  return tips;
}

function formatDuration(seconds) {
  if (seconds < 1) return 'Instantly';
  const units = [['year', 31557600], ['month', 2629800], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  const years = seconds / 31557600;
  if (years >= 1.38e10) return 'Longer than the age of the universe';
  if (years >= 1e9) return `${Math.round(years / 1e9)} billion years`;
  if (years >= 1e6) return `${Math.round(years / 1e6)} million years`;
  if (years >= 1000) return `${Math.round(years / 1000)} thousand years`;
  if (years >= 100) return `${Math.round(years / 100)} centuries`;
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      return `${n} ${name}${n === 1 ? '' : 's'}`;
    }
  }
}

if (typeof module !== 'undefined') module.exports = { analyze, formatDuration, ATTACKS, LEVELS };
