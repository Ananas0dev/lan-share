# Security model

LAN Share is an account-free service for trusted local networks. Anyone who can reach it can create shares and participate in discovery. Optional item passwords restrict protected content; they do not authenticate every network participant.

Stored-item passwords use salted PBKDF2. The server generates a private signing key under the data directory. Keep the entire data directory and backups private, use HTTPS for household access, and restrict filesystem permissions. Direct transfers are relayed through the server and are not end-to-end encrypted.

The recovered implementation has not had a comprehensive security audit or adversarial resource-exhaustion review. There is no global transfer quota or comprehensive rate limiting. Do not expose it directly to an untrusted network on the strength of per-item passwords alone.
