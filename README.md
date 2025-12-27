# Hidden Text Media

Hide encrypted text inside any media or binary file (video, audio, archive, etc.)
in a simple, cross-platform and reversible way.

This project appends encrypted data at the end of a file, without breaking its
original usability.

---

## Features

- AES-256-GCM encryption (authenticated)
- Fragmented encrypted blocks
- Optional expiration time
- Optional read limit
- Optional self-destruction on wrong key
- Optional media corruption after read
- Windows / Linux (Ubuntu, Kali)
- Auto-install required Python modules

Option	                Description
-k	                    Encryption key
-t	                    Expiration time in seconds
-r	                    Maximum read count
--destroy-on-fail	      Remove message if wrong key
--corrupt-after-read	  Corrupt media after read

Security Model

- AES-256-GCM
- PBKDF2 key derivation (300k iterations)
- Encrypted metadata
- Random padding and fragmentation
- No plaintext markers
Without the key, the embedded data is indistinguishable from random noise.

---

## Disclaimer

This project is for **educational and experimental purposes only**.
- Re-encoding the media will remove the hidden data
- Anyone with the file but without the key **cannot read the message**
- This is **not DRM**, but cryptographic protection

---

## Installation

Python **3.9+** required.
No manual dependency installation needed:
the script will automatically install missing modules.

---

## Usage

### Add hidden text
python text.py -text add "Hello\nWorld" to video.mp4
python text.py -text read video.mp4 -k mypassword/key

