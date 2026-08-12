"""Core account/authentication logic for the password protection system.

Kept free of any input()/print() calls so it can be unit tested directly
(see tests/test_account_system.py). All I/O lives in password_system.py.

Security notes (what changed from the original notebook version):
- Passwords and security-question answers are never stored in plain text.
  They're hashed with PBKDF2-HMAC-SHA256, a per-user random salt, and a
  high iteration count (OWASP-recommended minimum as of 2023).
- Verification uses a constant-time comparison (secrets.compare_digest) to
  avoid leaking timing information about how much of the hash matched.
- Passwords must be at least MIN_PASSWORD_LENGTH characters - the original
  4-digit numeric PIN only had 10,000 possible combinations, trivially
  brute-forced.
- Failed logins are rate-limited: after LOCKOUT_THRESHOLD consecutive
  failures, the account locks for LOCKOUT_SECONDS rather than permanently
  (the original locked forever with no way back except the reset flow).
- Accounts persist to a local JSON file (still only suitable for a personal
  CLI tool, not a real multi-user production system - see the README).
"""

import hashlib
import json
import os
import secrets
import time

PBKDF2_ITERATIONS = 260_000
MIN_PASSWORD_LENGTH = 8
LOCKOUT_THRESHOLD = 3
LOCKOUT_SECONDS = 300  # 5 minutes


def hash_secret(secret, salt=None):
    """Hash a password/answer with PBKDF2-HMAC-SHA256 and a random salt.
    Returns (salt_hex, hash_hex). Pass an existing salt to re-derive the
    same hash for verification."""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', secret.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_secret(secret, salt_hex, hash_hex):
    """Constant-time check of a secret against a stored salt+hash pair."""
    salt = bytes.fromhex(salt_hex)
    _, computed_hash = hash_secret(secret, salt)
    return secrets.compare_digest(computed_hash, hash_hex)


class AccountError(Exception):
    """Raised for account operation failures (bad username, wrong password,
    account locked, etc.) - the CLI catches these and prints a message."""


class AccountSystem:
    """Multi-user account system with hashed password storage, time-based
    login lockout, and secret-question password recovery."""

    def __init__(self, storage_path="accounts.json"):
        self.storage_path = storage_path
        self.users = {}
        self.attempts = {}
        self.locked_until = {}
        self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            self.users = data.get('users', {})
            self.attempts = {username: 0 for username in self.users}

    def _save(self):
        with open(self.storage_path, 'w') as f:
            json.dump({'users': self.users}, f, indent=2)

    def create_account(self, username, password, question, answer):
        """Create a new account. Raises AccountError on invalid input."""
        username = username.strip()
        if not username:
            raise AccountError("Username cannot be blank.")
        if username in self.users:
            raise AccountError("Username already exists.")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise AccountError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        if not question.strip() or not answer.strip():
            raise AccountError("Security question and answer are required.")

        pin_salt, pin_hash = hash_secret(password)
        answer_salt, answer_hash = hash_secret(answer.strip().lower())

        self.users[username] = {
            'pin_salt': pin_salt, 'pin_hash': pin_hash,
            'question': question,
            'answer_salt': answer_salt, 'answer_hash': answer_hash,
        }
        self.attempts[username] = 0
        self._save()

    def is_locked(self, username):
        """Return whether the account is currently locked out. Auto-expires
        the lock (and resets the attempt counter) once the timeout passes."""
        until = self.locked_until.get(username)
        if until is None:
            return False
        if time.time() >= until:
            del self.locked_until[username]
            self.attempts[username] = 0
            return False
        return True

    def lockout_remaining_seconds(self, username):
        until = self.locked_until.get(username, 0)
        return max(0, int(until - time.time()))

    def login(self, username, password):
        """Attempt login. Returns True/False. Raises AccountError for an
        unknown username or while the account is locked out."""
        if username not in self.users:
            raise AccountError("No such user.")
        if self.is_locked(username):
            raise AccountError(f"Account locked. Try again in {self.lockout_remaining_seconds(username)}s.")

        record = self.users[username]
        if verify_secret(password, record['pin_salt'], record['pin_hash']):
            self.attempts[username] = 0
            return True

        self.attempts[username] = self.attempts.get(username, 0) + 1
        if self.attempts[username] >= LOCKOUT_THRESHOLD:
            self.locked_until[username] = time.time() + LOCKOUT_SECONDS
        return False

    def remaining_attempts(self, username):
        return max(0, LOCKOUT_THRESHOLD - self.attempts.get(username, 0))

    def get_security_question(self, username):
        if username not in self.users:
            raise AccountError("No such user.")
        return self.users[username]['question']

    def reset_password(self, username, answer, new_password):
        """Reset a password via the security-question answer. Raises
        AccountError if the username is unknown, the answer is wrong, or
        the new password is too short."""
        if username not in self.users:
            raise AccountError("No such user.")
        record = self.users[username]
        if not verify_secret(answer.strip().lower(), record['answer_salt'], record['answer_hash']):
            raise AccountError("Incorrect answer.")
        if len(new_password) < MIN_PASSWORD_LENGTH:
            raise AccountError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

        pin_salt, pin_hash = hash_secret(new_password)
        record['pin_salt'] = pin_salt
        record['pin_hash'] = pin_hash
        self.attempts[username] = 0
        self.locked_until.pop(username, None)
        self._save()
