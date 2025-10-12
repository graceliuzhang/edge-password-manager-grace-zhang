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


def add_password(site: str, username: str, password: str) -> None:
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
    passwords = _load_json(PASSWORDS_FILE, [])

    passwords.append(entry)

    PASSWORDS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)


def get_passwords() -> list[dict]:
    """Retrieve all stored passwords.

    This will read from an encrypted JSON file and return a list
    of dictionaries containing site, username and password.  For now
    it raises `NotImplementedError`.

    Returns:
        A list of stored passwords.
    """
    return _load_json(PASSWORDS_FILE, [])


def list_password() -> None:
    """Print saved passwords in a simple, readable way."""
    passwords = get_passwords()
    if not passwords:
        print("No passwords saved yet.")
        return
    for entry in passwords:
        print(f"Site: {entry['site']}, Username: {entry['username']}, Password: {entry['password']}")


def search_sites(site_name: str) -> list[dict]:
    passwords = _load_json(PASSWORDS_FILE, [])
    if not passwords:
        print("No passwords found.")
        return []
    matches: list = []
    for entry in passwords:
        saved_site = entry["site"].lower()
        search_site = site_name.lower()
        if saved_site == search_site:
            matches.append(entry)
    
    if matches:
         for entry in matches:
            print(f"Site: {entry['site']}, Username: {entry['username']}, Password: {entry['password']}")
    else:
        print(f"No results found for {site_name}")
    return matches




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
                    user_input = input("Press 1 for Add Password, 2 for List Passwords, 3 for Search, q for Quit: ")
                    if user_input == "1":
                        new_site: str = input("Enter site: ")
                        new_username: str = input("Enter username: ")
                        new_password: str = input("Enter password: ")
                        add_password(new_site, new_username, new_password)
                        print("Password saved.")
                    elif user_input == "2":
                        list_password()
                    elif user_input == "3":
                        site_name: str = input("Enter site to search: ")
                        search_sites(site_name)
                    elif user_input == "q":
                        break
                    else:
                        print("Please input 1, 2, 3, or q")
            else:
                # If login failed, stop here or allow another try in the future
                pass
                    
        elif choice == "q":
            break
        else:
            print("Please input 1, 2, or q")


if __name__ == "__main__":
    main()
