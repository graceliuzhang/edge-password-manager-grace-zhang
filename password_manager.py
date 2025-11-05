"""Simple password manager (stub).

This module provides placeholder functions for a command-line password
manager.  Eventually it will allow users to register with a master
password, store encrypted passwords for various sites and retrieve them.
For now, it contains stubs that raise `NotImplementedError` and prints
a greeting when executed.
"""
import json
import hashlib
from pathlib import Path

# File paths
USER_DATA_FILE = Path("data/user_data.json")
PASSWORDS_FILE = Path("data/passwords.json")


def _load_json(path: Path, default):
    """Load JSON from a file, returning a default value if missing/empty/invalid.

    This prevents crashes like JSONDecodeError when a file exists but is empty.
    """
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, "r") as f:
                return json.load(f)
    except json.JSONDecodeError:
        # Treat invalid JSON as empty/default instead of crashing
        pass
    return default

import tempfile
import os
from datetime import datetime
import uuid
from shutil import copyfile

# === Integrity & Versioning ===
VERSION = 1
CHECKSUM_FILE = PASSWORDS_FILE.with_suffix(".sha256")
WRITE_BLOCKED = False  # flipped to True if integrity check fails at startup

# === Optional encryption (Track-specific security) ===
# - Derive a key from the master password using PBKDF2 (salt per user).
# - Encrypt passwords at rest with Fernet.
import base64
try:
    from cryptography.fernet import Fernet
    from hashlib import pbkdf2_hmac
    CRYPTO_AVAILABLE = True
except Exception:
    # If cryptography isn't installed, we still run, but store plaintext.
    CRYPTO_AVAILABLE = False
FernetCipher = None  # set after successful login


def _now_iso():
    return datetime.now().isoformat() + "Z"


def _checksum(path: Path) -> str:
    if not path.exists():
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def _validate_nonempty(value: str, field: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{field} cannot be empty.")
    # basic unsafe character blocking for this CLI context
    if any(c in value for c in ["\n", "\r", "{", "}", "\x00"]):
        raise ValueError(f"{field} contains invalid characters.")
    return value


def _safe_save(data: dict | list, path: Path):
    """Safely save JSON to disk with a simple backup.

    - If a previous file exists, make a copy with the .bak extension.
    - Write to a temporary file and then replace the original.
    - Update checksum file atomically.
    """
    global WRITE_BLOCKED
    if WRITE_BLOCKED:
        print("Refusing to write: integrity check failed. Use Import/Export to recover or recompute checksum.")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    # Timestamped backup for extra safety (keeps last state)
    ts_backup = path.with_suffix(f".{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak")
    if path.exists():
        try:
            copyfile(path, path.with_suffix(".bak"))
            copyfile(path, ts_backup)
        except Exception as e:
            # Backup failure shouldn't stop saving; just warn.
            print(f"Warning: couldn't back up {path}: {e}")
    fd, tmp = tempfile.mkstemp(prefix="tmp_", dir=path.parent, text=True)
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp, path)
        # update checksum
        CHECKSUM_FILE.write_text(_checksum(path), encoding="utf-8")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _verify_integrity_on_startup():
    """Verify checksum and set WRITE_BLOCKED if mismatch. Never crash."""
    global WRITE_BLOCKED
    try:
        saved = CHECKSUM_FILE.read_text(encoding="utf-8") if CHECKSUM_FILE.exists() else ""
        current = _checksum(PASSWORDS_FILE)
        if saved and current and saved != current:
            print("⚠ Integrity check FAILED — data may have been modified.")
            print("Writes are blocked to prevent accidental overwrite.")
            WRITE_BLOCKED = True
    except Exception:
        # If anything goes wrong, do not crash; just proceed read-only.
        WRITE_BLOCKED = True
        print("⚠ Integrity check could not be completed; proceeding read-only.")


def _encrypt_if_possible(plaintext: str) -> str:
    if CRYPTO_AVAILABLE and FernetCipher:
        try:
            return FernetCipher.encrypt(plaintext.encode()).decode()
        except Exception:
            pass
    return plaintext  # fallback to plaintext if crypto not available


def _maybe_decrypt(value: str) -> str:
    """Decrypt Fernet tokens; otherwise return as-is (supports legacy plaintext)."""
    if not isinstance(value, str):
        return ""
    if CRYPTO_AVAILABLE and FernetCipher and value.startswith("gAAAA"):
        try:
            return FernetCipher.decrypt(value.encode()).decode()
        except Exception:
            # Wrong key or corrupt token; show masked but indicate issue.
            return "[UNREADABLE]"
    return value


def _derive_key(master_password: str, salt: bytes) -> bytes:
    raw = pbkdf2_hmac("sha256", master_password.encode(), salt, 200_000)
    return base64.urlsafe_b64encode(raw)


def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password.

    You will hash and store the master password in a
    JSON file for authentication.  This stub does nothing.

    Args:
        username: The username for the account.
        master_password: The master password to use.
    """
    try:
        username = _validate_nonempty(username, "Username")
        master_password = _validate_nonempty(master_password, "Master password")
    except ValueError as e:
        print(f"Input error: {e}")
        return

    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
    # Load existing users safely (handles missing/empty file)
    users = _load_json(USER_DATA_FILE, {})

    # For encryption: store per-user salt (without storing key).
    # Backward-compatible: if existing value is a string, keep it; else use dict.
    if username in users and isinstance(users[username], dict):
        user_rec = users[username]
    else:
        user_rec = {}

    user_rec["hash"] = hashed_pw
    if CRYPTO_AVAILABLE:
        user_rec["salt"] = base64.b64encode(os.urandom(16)).decode()

    users[username] = user_rec

    USER_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USER_DATA_FILE, "w") as f:
        json.dump(users, f, indent = 4)


def add_password(site: str, username: str, password: str, notes: str = "", tags: list[str] | None = None) -> None:
    """Store a password for a given site.

    You will encrypt the password and save it to a JSON file,
    associating it with the site and username.  This stub does nothing.

    Args:
        site: The website or service name.
        username: The account username for the site.
        password: The password to store.
    """
    # Validate inputs (reject empty/malformed)
    try:
        site = _validate_nonempty(site, "Site")
        username = _validate_nonempty(username, "Username")
        password = _validate_nonempty(password, "Password")
    except ValueError as e:
        print(f"Input error: {e}")
        return

    # Load existing entries safely (handles missing/empty file)
    passwords = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    if isinstance(passwords, list):
        # migrate old format
        passwords = {"version": VERSION, "entries": passwords}

    # check for duplicates
    for entry in passwords["entries"]:
        if entry.get("site") == site and entry.get("username") == username:
            print("Duplicate found for (site, username).")
            choice = input("Skip (s), Overwrite (o), or Keep both (k)? ").lower().strip()
            if choice == "s":
                print("Skipped adding.")
                return
            elif choice == "o":
                entry.update({
                    "password": _encrypt_if_possible(password),
                    "notes": notes or "",
                    "tags": (tags or []),
                    "last_updated": _now_iso()
                })
                print("Overwritten existing entry.")
                _safe_save(passwords, PASSWORDS_FILE)
                return
            elif choice == "k":
                break

    # Choose a simple numeric ID: 1, 2, 3, ...
    existing_ids: list[int] = []
    for e in passwords["entries"]:
        try:
            existing_ids.append(int(e.get("id")))
        except (TypeError, ValueError):
            # Skip entries without numeric IDs
            pass
    next_id = max(existing_ids) + 1 if existing_ids else 1

    new_entry = {
        "id": next_id,
        "site": site,
        "username": username,
        "password": _encrypt_if_possible(password),
        "notes": notes or "",
        "tags": tags or [],
        "last_updated": _now_iso()
    }
    passwords["entries"].append(new_entry)
    _safe_save(passwords, PASSWORDS_FILE)
    print(f"Added new entry for {site} ({username}).")


def _load_entries() -> list[dict]:
    """Always return a simple list of password entries.

    The file might be stored as a plain list (old format)
    or as an object with an "entries" list (new format).
    This helper hides that detail so the rest of the code is simpler.
    """
    data = _load_json(PASSWORDS_FILE, [])
    if isinstance(data, list):
        return data
    # expect dict with entries
    return data.get("entries", [])


def get_passwords() -> list[dict]:
    """Retrieve all stored passwords.

    This will read from an encrypted JSON file and return a list
    of dictionaries containing site, username and password.  For now
    it raises `NotImplementedError`.

    Returns:
        A list of stored passwords.
    """
    return _load_entries()


def list_password() -> None:
    """Print saved passwords in a simple, readable way.

    If you choose not to reveal, the password is shown as **** with the same length.
    """
    passwords = get_passwords()
    if not passwords:
        print("No passwords saved yet.")
        return
    reveal = input("Reveal passwords? (y/N): ").lower() == "y"
    for p in passwords:
        # decrypt if needed (supports plaintext for backward-compat)
        pw_value = _maybe_decrypt(p.get('password', ''))
        pw = pw_value if reveal else '*' * len(pw_value if isinstance(pw_value, str) else "")
        print(f"Site: {p.get('site','?')}, Username: {p.get('username','?')}, Password: {pw}, ID: {p.get('id','?')}")


def search_sites(site_name: str) -> list[dict]:
    passwords = _load_entries()
    if not passwords:
        print("No passwords found.")
        return []
    matches: list[dict] = []
    for entry in passwords:
        saved_site = str(entry.get("site", "")).lower()
        search_site = (site_name or "").lower().strip()
        if saved_site == search_site:
            matches.append(entry)

    if matches:
        for entry in matches:
            # masked by default in search
            plain = _maybe_decrypt(entry.get('password',''))
            masked = '*' * len(plain if isinstance(plain, str) else "")
            print(f"Site: {entry.get('site','?')}, Username: {entry.get('username','?')}, Password: {masked}")
    else:
        print(f"No results found for {site_name}")
    return matches


def reveal_password(entry_id: str) -> None:
    """Show the full password for a single entry by its ID.

    If the entry isn't found (or IDs aren't present in older files), tell the user.
    """
    # Try new format first (with IDs)
    data = _load_json(PASSWORDS_FILE, [])
    entries = []
    if isinstance(data, dict):
        entries = data.get("entries", [])
    elif isinstance(data, list):
        # Old format has no IDs; just tell the user and list items
        print("Passwords were saved in an older format without IDs. Use 'List' to view them.")
        return

    for e in entries:
        if str(e.get("id")) == str(entry_id):
            plain = _maybe_decrypt(e.get('password',''))
            print(f"Site: {e.get('site','?')}, Username: {e.get('username','?')}, Password: {plain}, ID: {e.get('id', '')}")
            return
    print("No entry found with that ID.")


def login_user(username: str, master_password: str) -> bool:
    """Log in a user by checking their master password.

    This checks the entered password against the stored hash.

    Args:
        username: The username to log in.
        master_password: The password entered by the user.

    Returns:
        True if login is successful, False otherwise.
    """
    global FernetCipher
    # Check if user data file exists
    users = _load_json(USER_DATA_FILE, {})
    if not users:
        print("No users registered yet.")
        return False
    if username not in users:
        print("Username not found!")
        return False

    # Backward-compatible: users[username] can be string (old) or dict (new)
    rec = users.get(username)
    if isinstance(rec, dict):
        stored_hash = rec.get("hash")
    else:
        stored_hash = rec

    entered_hash = hashlib.sha256(master_password.encode()).hexdigest()
    if entered_hash == stored_hash:
        # Set Fernet cipher for this session (if available)
        if CRYPTO_AVAILABLE:
            try:
                salt_b = base64.b64decode(rec.get("salt")) if isinstance(rec, dict) and rec.get("salt") else os.urandom(16)
                key = _derive_key(master_password, salt_b)
                FernetCipher = Fernet(key)
            except Exception:
                FernetCipher = None
        print("Success!")
        return True
    else:
        print("Password is incorrect.")
        return False


def edit_password(entry_id: str) -> None:
    data = _load_json(PASSWORDS_FILE, {"entries": []})
    for e in data["entries"]:
        if str(e.get("id")) == str(entry_id):
            print("Leave blank to keep current value.")
            new_site = input(f"Site [{e['site']}]: ") or e['site']
            new_user = input(f"Username [{e['username']}]: ") or e['username']
            new_pw = input("Password (leave blank to keep): ") or _maybe_decrypt(e['password'])
            new_notes = input(f"Notes [{e.get('notes','')}]: ") or e.get('notes','')
            new_tags = input(f"Tags (comma, blank to keep): ")
            tags = [t.strip() for t in new_tags.split(",")] if new_tags else e.get("tags", [])
            # validate new values
            try:
                new_site = _validate_nonempty(new_site, "Site")
                new_user = _validate_nonempty(new_user, "Username")
                new_pw = _validate_nonempty(new_pw, "Password")
            except ValueError as ve:
                print(f"Input error: {ve}")
                return
            e.update({
                "site": new_site,
                "username": new_user,
                "password": _encrypt_if_possible(new_pw),
                "notes": new_notes,
                "tags": tags,
                "last_updated": _now_iso()
            })
            _safe_save(data, PASSWORDS_FILE)
            print("Entry updated.")
            return
    print("Entry not found.")


def delete_password(entry_id: str) -> None:
    data = _load_json(PASSWORDS_FILE, {"entries": []})
    # confirmation
    confirm = input(f"Delete entry {entry_id}? This cannot be undone. (y/N): ").lower().strip()
    if confirm != "y":
        print("Delete cancelled.")
        return
    before = len(data["entries"])
    data["entries"] = [e for e in data["entries"] if str(e.get("id")) != str(entry_id)]
    if len(data["entries"]) < before:
        _safe_save(data, PASSWORDS_FILE)
        print("Entry deleted.")
    else:
        print("No entry found with that ID.")


def export_passwords(path: str) -> None:
    # Export the whole structure as-is (preserves encryption if present)
    data = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Exported to {path}")


def import_passwords(path: str) -> None:
    existing = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    with open(path, "r") as f:
        new_data = json.load(f)
    # Handle collisions explicitly via add_password (prompts user)
    for entry in new_data.get("entries", []):
        # Try to decrypt if incoming passwords are encrypted with current session;
        # if not, pass through (add_password will re-encrypt if possible).
        incoming_pw = entry.get("password", "")
        if incoming_pw and incoming_pw.startswith("gAAAA"):
            # assume encrypted; attempt decrypt (if wrong key, keep token)
            maybe_plain = _maybe_decrypt(incoming_pw)
            if maybe_plain not in ("[UNREADABLE]", ""):
                incoming_pw = maybe_plain
        add_password(entry.get("site",""), entry.get("username",""), incoming_pw,
                     entry.get("notes", ""), entry.get("tags", []))
    print("Import completed.")


def _print_help():
    print("Commands:")
    print("  1=Add, 2=List, 3=Search, 4=Edit, 5=Delete, 6=Reveal, 7=Export, 8=Import, 9=Lock, help=Show this help, q=Quit")


def main() -> None:
    """Entry point for the password manager.

    When run directly, this prints a greeting.  You will replace this
    with registration, login and menu functionality in future ships.
    """
    print("Welcome to the Password Manager!")
    _verify_integrity_on_startup()
    
    while True:
        choice = input("Choose 1 for Registration or 2 for Login or q to Quit: ")
        if choice == "1":
            username = input("Enter username: ")
            master_password = input("Enter master password: ")
            register_user(username, master_password)
            print("Registration successful!")
        elif choice == "2":
            username = input("Enter username: ")
            master_password = input("Enter master password: ")
            logged_in = login_user(username, master_password)
            if logged_in:
                # Show a simple menu after successful login
                while True:
                    user_input = input(
                        "1=Add, 2=List, 3=Search, 4=Edit, 5=Delete, 6=Reveal, 7=Export, 8=Import, 9=Lock, help=Help, q=Quit: "
                    ).strip().lower()
                    if user_input == "1":
                        new_site = input("Site: ")
                        new_username = input("Username: ")
                        new_password = input("Password: ")
                        notes = input("Notes (optional): ")
                        tags = input("Tags (comma-separated): ")
                        add_password(new_site, new_username, new_password, notes, tags.split(",") if tags else [])
                    elif user_input == "2":
                        list_password()
                    elif user_input == "3":
                        site_name = input("Enter site to search: ")
                        search_sites(site_name)
                    elif user_input == "4":
                        entry_id = input("Enter entry id to edit: ")
                        edit_password(entry_id)
                    elif user_input == "5":
                        entry_id = input("Enter entry id to delete: ")
                        delete_password(entry_id)
                    elif user_input == "6":
                        entry_id = input("Enter entry id to reveal: ")
                        reveal_password(entry_id)
                    elif user_input == "7":
                        export_passwords("export.json")
                    elif user_input == "8":
                        import_passwords("export.json")
                    elif user_input == "9":
                        # lock: clear cipher and leave to login screen
                        global FernetCipher
                        FernetCipher = None
                        print("Locked.")
                        break
                    elif user_input == "help":
                        _print_help()
                    elif user_input == "q":
                        break
                    else:
                        print("Invalid option.")
            else:
                # If login failed, stop here or allow another try in the future
                pass
                    
        elif choice == "q":
            break
        else:
            print("Please input 1, 2, or q")


if __name__ == "__main__":
    main()
