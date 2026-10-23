# Password Strength Analyzer with Breach Detection

A browser-based tool that measures how strong a password really is. It calculates entropy, detects weak patterns that attackers exploit, estimates crack time under different attack scenarios, and checks whether the password appears in known data breaches without revealing the password, using k-anonymity.

## Features

| Feature | What it shows |
|---|---|
| Live strength meter | 5-level score (Very weak → Very strong) as you type |
| Entropy calculation | Step-by-step math: `L × log₂(N)`, then penalties for patterns |
| Pattern detection | Common passwords, dictionary words, leetspeak (`p@ssw0rd`), sequences (`abc`, `123`), keyboard walks (`qwerty`), repeats, years |
| Crack-time estimates | 4 scenarios, from rate-limited online attacks to GPU cracking of a stolen database |
| Breach check | Queries the *Have I Been Pwned* Pwned Passwords database using k-anonymity |
| Secure generator | 16-character random password from the browser's cryptographic random number generator |

## How to run

No installation is needed. Python is only used as a simple local web server.

```bash
cd password-analyzer
python3 -m http.server 8000
```

Then open <http://localhost:8000> in a browser. The breach check needs an internet connection; everything else works offline.

## Project structure

```
password-analyzer/
├── index.html     Page layout
├── style.css      Styling (supports light and dark mode)
├── wordlists.js   Common passwords and dictionary words
├── analyzer.js    Core logic: entropy, pattern detection, crack time
└── app.js         UI wiring, breach check, password generator
```

## How it works

### 1. Entropy (how many guesses are needed)

Entropy measures unpredictability in **bits**. Each extra bit doubles the number of guesses an attacker needs.

```
Entropy = L × log₂(N)
  L = password length
  N = size of the character pool (lowercase 26 + uppercase 26 + digits 10 + symbols 33)
```

Example: a random 12-character password using all four character types has `12 × log₂(95) ≈ 78.8 bits`.

### 2. Pattern penalties (why "naive" entropy lies)

Attackers don't guess randomly. They try common passwords, dictionary words, and predictable patterns first. The tool finds these and replaces their naive cost with a realistic one:

| Pattern | Realistic cost |
|---|---|
| Whole password on the common list | log₂(rank), e.g. #1 = 0 bits |
| Dictionary word | ~17 bits (one word out of ~100,000), +1 for capitals, +1 for leetspeak |
| Sequence (`abcd`, `4321`) | ~log₂(26) + log₂(length) + 1 bits |
| Keyboard walk (`qwerty`) | ~log₂(100) + log₂(length) bits |
| Repeats (`aaaa`, `abcabc`) | cost of one copy + log₂(count) |
| Year (`1998`, `2024`) | ~7 bits (one of 150 likely years) |

So `Password2024!` looks complex (uppercase, digits, symbol, 13 characters = 85 naive bits) but scores only **~31 bits**, because it is just a dictionary word, a year and a symbol.

### 3. Crack time

```
Average guesses = 2^entropy ÷ 2
Time = guesses ÷ attacker's guesses per second
```

| Scenario | Speed |
|---|---|
| Online, rate-limited | ~100 guesses/hour |
| Online, no rate limit | ~10 guesses/second |
| Offline, slow hash (bcrypt) | ~10,000 guesses/second |
| Offline, fast hash (MD5) on a GPU | ~100 billion guesses/second |

This shows why **how the website stores passwords** (bcrypt vs MD5) matters as much as the password itself.

### 4. Breach check with k-anonymity

Sending a password to a server to check it would itself be a security risk. Instead:

1. The browser computes the **SHA-1 hash** of the password locally, e.g. `05DE2F6CD41FC2938A433DDBE82F999EF5805089`
2. Only the **first 5 characters** (`05DE2`) are sent to `api.pwnedpasswords.com/range/05DE2`
3. The server returns **all** leaked hash endings that start with that prefix (usually 1,000–2,000 of them)
4. The browser checks locally whether the rest of the hash is in that list

The server never learns the password or even its full hash, because the real one is hidden among more than 1,000 others. This is **k-anonymity**.

## Sample results

| Password | Effective entropy | Rating | GPU crack time | Why |
|---|---|---|---|---|
| `123456` | 0 bits | Very weak | Instantly | #1 most common password |
| `P@ssw0rd` | 3 bits | Very weak | Instantly | Leetspeak of a common password |
| `qwerty123` | 4 bits | Very weak | Instantly | Common password / keyboard walk |
| `rahul@1998` | 30 bits | Weak | Instantly | Name + symbol + birth year |
| `Password2024!` | 31 bits | Weak | Instantly | Word + year; found 3,972 times in breaches |
| `Gh7$kq` | 39 bits | Weak | 4 seconds | Random but too short |
| `x7#Kq9!mZ2@vLp4$` | 105 bits | Very strong | Longer than the universe's age | Long and random |

## Limitations

- The built-in word lists are small (117 common passwords, 112 words). Real attackers use lists with millions of entries, such as `rockyou.txt`, so passphrases made of words not in the list (e.g. `correct horse battery staple`) are overestimated.
- Crack-time figures are estimates based on typical hardware speeds.
- The breach check depends on the Have I Been Pwned API being reachable.

## Future scope

- Load a larger dictionary (e.g. top 100,000 passwords) for more accurate scoring
- Browser extension that checks passwords on sign-up forms
- Passphrase generator (random words, as in Diceware)

## Ethics

The tool only analyses passwords typed into it by the user. Nothing is stored, and only a 5-character hash prefix leaves the device. Never test other people's real passwords.
