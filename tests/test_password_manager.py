"""Tests for the implemented password manager functions.

These tests isolate storage by redirecting the data files to a tmp path.
"""

from pathlib import Path
import builtins
import io
import pytest

import password_manager as pm


def use_tmp_storage(tmp_path: Path) -> None:
    """Point the password manager to temp JSON files so tests don't touch real data."""
    pm.USER_DATA_FILE = tmp_path / "user_data.json"
    pm.PASSWORDS_FILE = tmp_path / "passwords.json"


def test_register_and_login(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    # No users yet -> login should fail
    assert pm.login_user("alice", "secret") is False

    # Register and then login should succeed with correct password
    pm.register_user("alice", "secret")
    assert pm.login_user("alice", "secret") is True
    # Wrong password should fail
    assert pm.login_user("alice", "wrong") is False
    # Unknown user should fail
    assert pm.login_user("bob", "secret") is False


def test_add_and_get_passwords(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    # Ensure encryption is off for deterministic assertions in this test
    if hasattr(pm, "FernetCipher"):
        pm.FernetCipher = None
    # Add two distinct passwords
    pm.add_password("gmail", "alice", "a1")
    pm.add_password("github", "alice", "a2")
    items = pm.get_passwords()
    # Should be a list of dicts
    assert isinstance(items, list)
    assert len(items) == 2
    # Check basic fields and that a simple numeric ID exists
    assert {"site", "username", "password"}.issubset(items[0].keys())
    assert isinstance(items[0].get("id"), (int, type(None)))


def test_search_sites(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    pm.add_password("example.com", "alice", "pw1")
    pm.add_password("example.com", "bob", "pw2")
    pm.add_password("other.com", "bob", "pw3")

    results = pm.search_sites("example.com")
    assert isinstance(results, list)
    assert len(results) == 2
    assert all(r.get("site") == "example.com" for r in results)


def test_list_password_masks_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    use_tmp_storage(tmp_path)
    # Ensure encryption is off for predictable masking length
    if hasattr(pm, "FernetCipher"):
        pm.FernetCipher = None
    pm.add_password("gmail", "alice", "secretpw")

    # list_password asks if we want to reveal; answer 'n' to keep masked
    monkeypatch.setattr(builtins, "input", lambda _: "n")
    pm.list_password()
    out = capsys.readouterr().out
    assert "secretpw" not in out
    assert "*" in out  # masked output should appear (length may vary)


def test_invalid_input_no_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Functions should not crash on obviously invalid input; they should fail cleanly."""
    use_tmp_storage(tmp_path)
    # login with no users and empty username/password -> should return False, not crash
    assert pm.login_user("", "") is False
    # search with empty site string -> should return []
    assert pm.search_sites("") == []


def test_duplicate_handling_skip_overwrite_keepboth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_tmp_storage(tmp_path)
    # Ensure encryption is off for deterministic comparisons of stored values
    if hasattr(pm, "FernetCipher"):
        pm.FernetCipher = None
    # Start with one entry
    pm.add_password("gmail", "alice", "pw1")
    first = pm.get_passwords()[0]["password"]

    # 1) Skip duplicate
    monkeypatch.setattr(__import__('builtins'), "input", lambda _: "s")
    pm.add_password("gmail", "alice", "pw2")
    items = pm.get_passwords()
    assert len(items) == 1
    # unchanged (same stored value)
    assert items[0]["password"] == first

    # Reset storage
    use_tmp_storage(tmp_path / "case2")
    pm.add_password("gmail", "alice", "pw1")
    before = pm.get_passwords()[0]["password"]
    # 2) Overwrite duplicate
    monkeypatch.setattr(__import__('builtins'), "input", lambda _: "o")
    pm.add_password("gmail", "alice", "pw2")
    items = pm.get_passwords()
    assert len(items) == 1
    after = items[0]["password"]
    assert after != before  # stored value changed

    # Reset storage
    use_tmp_storage(tmp_path / "case3")
    pm.add_password("gmail", "alice", "pw1")
    # 3) Keep both
    monkeypatch.setattr(__import__('builtins'), "input", lambda _: "k")
    pm.add_password("gmail", "alice", "pw2")
    items = pm.get_passwords()
    assert len(items) == 2
    # Two distinct stored values expected
    assert items[0]["password"] != items[1]["password"]


def test_missing_ids_old_format_is_supported_for_list_and_search(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    use_tmp_storage(tmp_path)
    # Manually create an old-format file (list of dicts, no id field)
    data = [
        {"site": "gmail", "username": "alice", "password": "pw1"},
        {"site": "github", "username": "alice", "password": "pw2"},
    ]
    pm.PASSWORDS_FILE.write_text(__import__('json').dumps(data))

    # Listing should work and not crash
    # Simulate "do not reveal"
    import builtins as _b
    orig_input = _b.input
    _b.input = lambda _: "n"
    try:
        pm.list_password()
    finally:
        _b.input = orig_input

    out = capsys.readouterr().out
    assert "gmail" in out and "github" in out

    # Reveal by ID should inform about older format and not crash
    pm.reveal_password("1")
    out2 = capsys.readouterr().out
    assert "older format" in out2.lower()


@pytest.mark.xfail(reason="Integrity check not implemented yet")
def test_integrity_check_detects_tampered_files(tmp_path: Path) -> None:
    use_tmp_storage(tmp_path)
    pm.add_password("gmail", "alice", "pw1")
    # Simulate tampering: directly edit password file contents
    raw = pm.PASSWORDS_FILE.read_text()
    pm.PASSWORDS_FILE.write_text(raw.replace("pw1", "hacked"))
    # Expect some integrity verifier to detect mismatch (not yet implemented)
    assert pm.check_integrity() is False  # placeholder API


@pytest.mark.xfail(reason="Encryption not implemented yet")
def test_encryption_decryption_round_trip() -> None:
    secret = "my password"
    key = "masterkey"
    # Expect encrypt/decrypt helpers to exist and round-trip exactly (not yet implemented)
    cipher = pm.encrypt(secret, key)
    plain = pm.decrypt(cipher, key)
    assert plain == secret