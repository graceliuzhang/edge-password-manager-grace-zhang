# Security Overview

## Validation
- Rejects empty or malformed site, username, and password fields.
- Disallows unsafe characters (newlines, braces, null bytes).
- Prompts user rather than raising unhandled exceptions.

## Integrity & Versioning
- Each data file stores `version: <int>`.
- A SHA-256 checksum is computed and stored in `passwords.sha256`.
- On startup, mismatches trigger a warning and block writes until confirmed safe.
- `.bak` and timestamped backups are created before every save.

## Encryption
- Uses PBKDF2 (SHA-256, 200k iterations) to derive a key from the master password.
- Passwords encrypted with Fernet (AES-128 in CBC mode + HMAC).
- Salt is stored per user; key is **never written to disk**.
- Supports “lock” to clear key from memory during runtime.

## Known Limitations
- Master password stored as SHA-256 hash (not salted; sufficient for local use but not production-grade).
- Integrity checks protect against file modification but not deletion.
- Does not yet include per-entry MACs or multiple-user sharing.
- No clipboard integration (manual copy only).