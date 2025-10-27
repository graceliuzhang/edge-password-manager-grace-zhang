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
    pm.add_password("gmail", "alice", "secretpw")

    # list_password asks if we want to reveal; answer 'n' to keep masked
    monkeypatch.setattr(builtins, "input", lambda _: "n")
    pm.list_password()
    out = capsys.readouterr().out
    assert "secretpw" not in out
    assert "*******" in out  # masked output should appear