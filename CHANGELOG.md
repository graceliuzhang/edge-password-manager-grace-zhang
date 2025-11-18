Ship 6 — Security Upgrade & CLI Improvements
Added

Input validation for all fields (site, username, password).

SHA-256 integrity checking with write-blocking when mismatched.

Version metadata stored in password file.

Encryption at rest using PBKDF2-derived Fernet key.

Lock command to clear active encryption key.

Help command listing all actions.

Timestamped backups created automatically on every save.

Improved

Safe-save now enforces atomic writes and updates checksum.

Listing masks passwords by default; reveal only when requested.

Search results hide passwords instead of showing plaintext.

Edit flow decrypts, validates, and re-encrypts credentials.

Import respects collisions and triggers duplicate-resolution logic.

Fixed

Better handling of malformed JSON and empty files.

Prevents accidental overwrite on integrity failure.

Improves backward compatibility with older plaintext formats.