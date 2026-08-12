# Password Protection System

This project started as a Jupyter notebook where I worked through building a login system from scratch, one idea at a time. The notebook ([`password system.ipynb`](password%20system.ipynb)) is left in the repo on purpose - it's a record of that process: a single hardcoded PIN check, then a class-based single-user login, then a multi-user account system with login attempts and a lockout, and finally an attempt at password recovery using a security question.

Once the logic was worked out in the notebook, I rewrote it properly as a standalone Python project (`account_system.py` and `password_system.py`), fixing the security problems that came from focusing on "does it work" rather than "is it actually safe" while I was learning.

## What I fixed going from the notebook to the .py version

The notebook stored every password and every security-question answer as plain text - literally readable if you opened the underlying data. It also only accepted a 4-digit PIN, which is just 10,000 possible combinations, easy to guess or brute-force. And once the account lockout triggered, there was no way for it to un-lock itself short of a manual reset.

In the rewrite:

- Passwords and security-question answers are hashed with PBKDF2-HMAC-SHA256, salted per user, at 260,000 iterations - never stored as plain text.
- Passwords must be at least 8 characters, not a 4-digit PIN.
- A locked account now unlocks itself automatically after 5 minutes instead of staying locked forever.
- Accounts persist between runs in `accounts.json` (only the hashes are saved, never the real password).
- Every place a secret is typed uses `getpass()`, so nothing gets echoed to the terminal.
- While reading back through the notebook I also found a cell where `break` was used outside of any loop - that's a Python `SyntaxError`, so that particular cell couldn't have actually produced the output sitting next to it. It doesn't carry over into the rewrite.

## Project structure

`account_system.py` holds all the actual account logic - hashing, login, lockout, persistence - with no `input()` or `print()` calls in it, so it can be tested directly. `password_system.py` is the interactive command-line menu that calls into it. `tests/test_account_system.py` has 19 tests covering account creation, login, lockout (including it expiring correctly), and password reset.

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install pytest          # only needed to run the tests
python password_system.py
```

You get a menu to create an account, log in, or reset a password using your security question.

## Running the tests

```bash
pytest tests/
```

## What this still isn't

This is a personal project, not production authentication. The account file sits unencrypted on disk (just the hashes, but still). Security questions are a weaker recovery method than something like email or SMS verification - I kept it because it's what I originally built and wanted to secure properly, not because I'd recommend it for anything real. And there's no handling for two processes writing to `accounts.json` at the same time.

## Author

Avwerosuo Peter Imoniose
