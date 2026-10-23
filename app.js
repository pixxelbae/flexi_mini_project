// Page wiring: live analysis as you type, show/hide, generator, and breach check.

const $ = id => document.getElementById(id);
const input = $('password');

// Last breach check result: { pw, count, hash, candidates } or { pw, error }.
let breach = null;

// Builds an element with plain text content (never innerHTML, so typed text can't inject HTML).
function el(tag, className, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  for (const c of children) node.append(c);
  return node;
}

function formatGuesses(n) {
  if (n < 1e6) return Math.round(n).toLocaleString();
  const [mantissa, exp] = n.toExponential(1).split('e');
  return `${mantissa} × 10^${Number(exp)}`;
}

function render() {
  const pw = input.value;
  const r = analyze(pw);
  $('results').hidden = !r;

  const breached = r && breach && breach.pw === pw && breach.count > 0;
  const level = breached ? 0 : r ? r.level : -1;
  [...$('meter').children].forEach((seg, i) => { seg.className = i <= level ? `lvl${level}` : ''; });

  if (!r) {
    $('level').textContent = 'Waiting for input';
    $('level').className = 'level';
    $('bits').textContent = '';
    return;
  }

  $('level').textContent = breached ? 'Very weak (found in breaches)' : r.label;
  $('level').className = `level lvl${level}`;
  $('bits').textContent = `${r.bits.toFixed(1)} bits of entropy`;

  $('crack-table').replaceChildren(...r.crackTimes.map(a => el('tr', null,
    el('td', null, el('div', 'attack', a.name), el('div', 'detail', a.detail)),
    el('td', 'time', breached ? 'Instantly' : formatDuration(a.seconds)),
  )));

  $('checklist').replaceChildren(...[...r.checks, { label: 'Not found in data breaches', ok: breach && breach.pw === pw && breach.count === 0 ? true : breached ? false : null }]
    .map(c => el('li', null,
      el('span', `mark ${c.ok ? 'ok' : c.ok === false ? 'bad' : ''}`, c.ok ? '✓' : c.ok === false ? '✗' : '?'),
      c.label + (c.ok === null ? ' (run the check below)' : ''),
    )));

  const log2N = Math.log2(r.pool.size);
  const rows = [
    ['Length (L)', `${r.length} characters`],
    ['Character pool (N)', `${r.pool.classes.map(c => `${c.name} ${c.size}`).join(' + ')} = ${r.pool.size}`],
    ['Naive entropy', `L × log₂(N) = ${r.length} × ${log2N.toFixed(2)} = ${r.naiveBits.toFixed(1)} bits`],
    ['After pattern penalties', `${r.bits.toFixed(1)} bits`],
    ['Average guesses needed', `2^${r.bits.toFixed(1)} ÷ 2 ≈ ${formatGuesses(r.guesses)}`],
  ];
  $('math').replaceChildren(...rows.flatMap(([k, v]) => [el('dt', null, k), el('dd', null, v)]));

  $('patterns').replaceChildren(...(r.patterns.length
    ? r.patterns.map(p => el('li', null, el('code', null, p.text), ` ${p.message} `, el('span', 'cost', `(worth only ${p.bits.toFixed(1)} bits)`)))
    : [el('li', 'muted', 'None found.')]));

  $('suggestions').replaceChildren(...r.suggestions.map(s => el('li', null, s)));

  renderBreach(pw);
}

function renderBreach(pw) {
  const result = $('breach-result');
  const steps = $('breach-steps');
  const current = breach && breach.pw === pw ? breach : null;
  result.hidden = steps.hidden = !current;
  if (!current) return;

  if (current.error) {
    result.className = 'breach-result error';
    result.textContent = current.error;
    steps.hidden = true;
    return;
  }

  const { hash, count, candidates } = current;
  result.className = `breach-result ${count ? 'found' : 'safe'}`;
  result.textContent = count
    ? `Found ${count.toLocaleString()} times in known data breaches. Do not use this password.`
    : 'Not found in any known data breach.';

  steps.replaceChildren(
    el('li', null, 'Your browser computed the SHA-1 hash locally: ', el('code', null, el('mark', null, hash.slice(0, 5)), hash.slice(5))),
    el('li', null, 'Only the first 5 characters were sent to the server: ', el('code', null, hash.slice(0, 5))),
    el('li', null, `The server returned ${candidates.toLocaleString()} hash endings that start with that prefix. It cannot tell which one (if any) is yours.`),
    el('li', null, `Your browser compared them locally: ${count ? 'a match was found.' : 'no match.'}`),
  );
}

async function sha1Hex(text) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function checkBreach() {
  const pw = input.value;
  if (!pw) return;
  const btn = $('breach-btn');
  btn.disabled = true;
  btn.textContent = 'Checking…';
  try {
    const hash = await sha1Hex(pw);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const lines = (await res.text()).trim().split('\n');
    const match = lines.find(line => line.split(':')[0] === hash.slice(5));
    breach = { pw, hash, candidates: lines.length, count: match ? parseInt(match.split(':')[1], 10) : 0 };
  } catch {
    breach = { pw, error: 'Could not reach the breach database. Check your internet connection and try again.' };
  } finally {
    btn.disabled = false;
    btn.textContent = 'Check breaches';
  }
  render();
}

// Uniformly random password using the browser's cryptographic random number generator.
function generatePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?';
  const limit = Math.floor(2 ** 32 / chars.length) * chars.length; // avoid modulo bias
  const buf = new Uint32Array(1);
  let out = '';
  while (out.length < length) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) out += chars[buf[0] % chars.length];
  }
  return out;
}

function setVisible(visible) {
  input.type = visible ? 'text' : 'password';
  $('toggle').textContent = visible ? 'Hide' : 'Show';
}

input.addEventListener('input', render);
$('toggle').addEventListener('click', () => setVisible(input.type === 'password'));
$('generate').addEventListener('click', () => {
  input.value = generatePassword();
  setVisible(true);
  render();
});
$('breach-btn').addEventListener('click', checkBreach);
input.addEventListener('keydown', e => { if (e.key === 'Enter') checkBreach(); });

render();
