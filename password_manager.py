"""Simple password manager (stub).

This module provides placeholder functions for a command‑line password
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

VERSION = 1


def _now_iso():
    return datetime.now().isoformat() + "Z"


def _safe_save(data: dict | list, path: Path):
    """Safely save JSON to disk with a simple backup.

    - If a previous file exists, make a copy with the .bak extension.
    - Write to a temporary file and then replace the original.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            copyfile(path, path.with_suffix(".bak"))
        except Exception as e:
            # Backup failure shouldn't stop saving; just warn.
            print(f"Warning: couldn't back up {path}: {e}")
    fd, tmp = tempfile.mkstemp(prefix="tmp_", dir=path.parent, text=True)
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)



def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password.

    You will hash and store the master password in a
    JSON file for authentication.  This stub does nothing.

    Args:
        username: The username for the account.
        master_password: The master password to use.
    """
    hashed_pw = hashlib.sha256(master_password.encode()).hexdigest()
    # Load existing users safely (handles missing/empty file)
    users = _load_json(USER_DATA_FILE, {})

    # save or update user
    users[username] = hashed_pw

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
    # Store a password for a given site.
    entry = {"site": site, "username": username, "password": password}

    # Load existing entries safely (handles missing/empty file)
    passwords = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    if isinstance(passwords, list):
        # migrate old format
        passwords = {"version": VERSION, "entries": passwords}

    # check for duplicates
    for entry in passwords["entries"]:
        if entry["site"] == site and entry["username"] == username:
            print("Duplicate found for (site, username).")
            choice = input("Skip (s), Overwrite (o), or Keep both (k)? ").lower()
            if choice == "s":
                print("Skipped adding.")
                return
            elif choice == "o":
                entry.update({
                    "password": password,
                    "notes": notes,
                    "tags": tags or [],
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
        "password": password,
        "notes": notes,
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
        # Use dictionary keys directly: p['password'] (do NOT convert 'password' to a number)
        pw_value = p.get('password', '')
        pw = pw_value if reveal else '*' * len(pw_value)
        print(f"Site: {p.get('site','?')}, Username: {p.get('username','?')}, Password: {pw}, ID: {p.get('id','?')}")


def search_sites(site_name: str) -> list[dict]:
    passwords = _load_entries()
    if not passwords:
        print("No passwords found.")
        return []
    matches: list[dict] = []
    for entry in passwords:
        saved_site = str(entry.get("site", "")).lower()
        search_site = site_name.lower()
        if saved_site == search_site:
            matches.append(entry)

    if matches:
        for entry in matches:
            print(f"Site: {entry.get('site','?')}, Username: {entry.get('username','?')}, Password: {entry.get('password','')}")
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
            print(f"Site: {e.get('site','?')}, Username: {e.get('username','?')}, Password: {e.get('password','')}, ID: {e.get('id', '')}")
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
    # Check if user data file exists
    users = _load_json(USER_DATA_FILE, {})
    if not users:
        print("No users registered yet.")
        return False
    if username not in users:
        print("Username not found!")
        return False
    entered_hash = hashlib.sha256(master_password.encode()).hexdigest()
    stored_hash = users.get(username)
    if entered_hash == stored_hash:
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
            new_pw = input("Password (leave blank to keep): ") or e['password']
            new_notes = input(f"Notes [{e.get('notes','')}]: ") or e.get('notes','')
            new_tags = input(f"Tags (comma, blank to keep): ")
            tags = [t.strip() for t in new_tags.split(",")] if new_tags else e.get("tags", [])
            e.update({
                "site": new_site,
                "username": new_user,
                "password": new_pw,
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
    before = len(data["entries"])
    data["entries"] = [e for e in data["entries"] if str(e.get("id")) != str(entry_id)]
    if len(data["entries"]) < before:
        _safe_save(data, PASSWORDS_FILE)
        print("Entry deleted.")
    else:
        print("No entry found with that ID.")


def export_passwords(path: str) -> None:
    data = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    with open(path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Exported to {path}")

def import_passwords(path: str) -> None:
    existing = _load_json(PASSWORDS_FILE, {"version": VERSION, "entries": []})
    with open(path, "r") as f:
        new_data = json.load(f)
    for entry in new_data.get("entries", []):
        add_password(entry["site"], entry["username"], entry["password"],
                     entry.get("notes", ""), entry.get("tags", []))
    print("Import completed.")





def main() -> None:
    """Entry point for the password manager.

    When run directly, this prints a greeting.  You will replace this
    with registration, login and menu functionality in future ships.
    """
    print("Welcome to the Password Manager!")
    
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
                        "1=Add, 2=List, 3=Search, 4=Edit, 5=Delete, 6=Reveal, 7=Export, 8=Import, q=Quit: "
                    )
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
