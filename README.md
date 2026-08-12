# 🔐 Password Protection System

A small CLI account system: create an account, log in, and recover a
forgotten password via a security question - with real password hygiene
underneath, not just a demo.

This started as [`password system.ipynb`](password%20system.ipynb), a
notebook showing the step-by-step build-up from a single hardcoded 4-digit
PIN to a multi-user system with lockout and password recovery. This repo
now also has a proper `.py` version with the security holes fixed.

---

## What changed from the notebook version

The notebook was a good learning exercise, but had real problems if taken
at face value as a "password protection system":

| Issue in the notebook | Fixed in `account_system.py` |
|---|---|
| Passwords stored in plain text | Hashed with PBKDF2-HMAC-SHA256 (260,000 iterations) + a random salt per user |
| 4-digit numeric PIN only (10,000 possible values - trivially brute-forced) | Passwords of any length, minimum 8 characters |
| Security-question answers stored in plain text | Hashed the same way as passwords |
| Account lockout was permanent until a manual reset | Lockout auto-expires after 5 minutes |
| No persistence - accounts vanished when the program exited | Accounts persist to a local `accounts.json` (hashes only, never plaintext) |
| Inconsistent use of `input()` vs `getpass()` for secrets | `getpass()` used everywhere a secret is entered, so it's never echoed to the screen |
| One cell had a `break` outside any loop - a hard `SyntaxError` | N/A - rewritten from scratch |

---

## Usage

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install pytest          # only needed to run the tests
python password_system.py
```

You'll get a menu to create an account, log in, or reset a password via
your security question.

---

## Project structure

- `account_system.py` - the actual account logic (hashing, lockout,
  persistence). No `input()`/`print()` calls, so it's directly unit
  testable.
- `password_system.py` - the interactive CLI that drives `account_system.py`.
- `tests/test_account_system.py` - pytest tests covering hashing, account
  creation, login, lockout (including expiry), and password reset.

## Testing

```bash
pytest tests/
```

---

## Honest limitations

This is a personal CLI tool, not production authentication infrastructure:

- Accounts are stored in a plain JSON file on disk (hashed values only,
  but no encryption at rest, no access control on the file itself).
- Security-question recovery is inherently weaker than something like
  email/SMS verification or TOTP - answers can sometimes be guessed or
  looked up. It's kept here because it's part of what the original
  notebook explored, not because it's the strongest option available.
- No concurrent-access handling - not designed for multiple processes
  writing to the same `accounts.json` at once.

For anything beyond a personal/learning project, use a real auth provider
or a well-audited library (e.g. `passlib`, `argon2-cffi`) instead of
hand-rolled hashing like this.

---

## Author

**Avwerosuo Peter Imoniose**
