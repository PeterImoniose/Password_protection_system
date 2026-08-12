"""Unit tests for account_system.py."""

import sys
import os
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from account_system import AccountSystem, AccountError, hash_secret, verify_secret


@pytest.fixture
def system(tmp_path):
    return AccountSystem(storage_path=str(tmp_path / "accounts.json"))


# ── hashing ──────────────────────────────────────────────────────────────────

def test_hash_and_verify_roundtrip():
    salt, digest = hash_secret("mypassword1")
    assert verify_secret("mypassword1", salt, digest)
    assert not verify_secret("wrongpassword", salt, digest)


def test_hash_is_never_plaintext():
    salt, digest = hash_secret("mypassword1")
    assert "mypassword1" not in digest
    assert "mypassword1" not in salt


def test_same_secret_different_salts_gives_different_hashes():
    salt1, digest1 = hash_secret("mypassword1")
    salt2, digest2 = hash_secret("mypassword1")
    assert salt1 != salt2
    assert digest1 != digest2


# ── create_account ───────────────────────────────────────────────────────────

def test_create_account_success(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    assert "alice" in system.users
    assert system.users["alice"]["pin_hash"] != "supersecret1"


def test_create_account_duplicate_username(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    with pytest.raises(AccountError):
        system.create_account("alice", "anotherpass1", "q", "a")


def test_create_account_short_password(system):
    with pytest.raises(AccountError):
        system.create_account("bob", "short", "q", "a")


def test_create_account_blank_username(system):
    with pytest.raises(AccountError):
        system.create_account("   ", "supersecret1", "q", "a")


def test_create_account_missing_security_question(system):
    with pytest.raises(AccountError):
        system.create_account("bob", "supersecret1", "", "a")


# ── login ────────────────────────────────────────────────────────────────────

def test_login_success(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    assert system.login("alice", "supersecret1") is True


def test_login_wrong_password(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    assert system.login("alice", "wrongpassword") is False


def test_login_unknown_user(system):
    with pytest.raises(AccountError):
        system.login("nobody", "whatever1")


def test_login_resets_attempts_on_success(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    system.login("alice", "wrongpassword")
    assert system.remaining_attempts("alice") == 2
    system.login("alice", "supersecret1")
    assert system.remaining_attempts("alice") == 3


# ── lockout ──────────────────────────────────────────────────────────────────

def test_lockout_after_threshold(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    for _ in range(3):
        system.login("alice", "wrongpassword")
    assert system.is_locked("alice")


def test_locked_account_rejects_even_correct_password(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    for _ in range(3):
        system.login("alice", "wrongpassword")
    with pytest.raises(AccountError):
        system.login("alice", "supersecret1")


def test_lockout_expires_after_timeout(system, monkeypatch):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    for _ in range(3):
        system.login("alice", "wrongpassword")
    assert system.is_locked("alice")

    future = time.time() + 301
    monkeypatch.setattr(time, "time", lambda: future)
    assert not system.is_locked("alice")
    assert system.login("alice", "supersecret1") is True


# ── password reset ───────────────────────────────────────────────────────────

def test_reset_password_success(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    system.reset_password("alice", "Tiger", "newpassword1")  # answer is case-insensitive
    assert system.login("alice", "newpassword1") is True
    assert system.login("alice", "supersecret1") is False


def test_reset_password_wrong_answer(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    with pytest.raises(AccountError):
        system.reset_password("alice", "wronganswer", "newpassword1")


def test_reset_password_unlocks_account(system):
    system.create_account("alice", "supersecret1", "pet?", "tiger")
    for _ in range(3):
        system.login("alice", "wrongpassword")
    assert system.is_locked("alice")

    system.reset_password("alice", "tiger", "newpassword1")
    assert not system.is_locked("alice")
    assert system.login("alice", "newpassword1") is True


# ── persistence ──────────────────────────────────────────────────────────────

def test_persistence_across_instances(tmp_path):
    path = str(tmp_path / "accounts.json")
    system1 = AccountSystem(storage_path=path)
    system1.create_account("alice", "supersecret1", "pet?", "tiger")

    system2 = AccountSystem(storage_path=path)
    assert system2.login("alice", "supersecret1") is True
