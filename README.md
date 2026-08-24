# secure-secrets-vault
CLI secrets manager built from scratch. AES-256-GCM authenticated encryption, Argon2id key derivation, atomic writes with fsync, rollback detection. Uses audited primitives (cryptography, argon2-cffi) — architecture, not crypto internals, is the from-scratch part. Local storage, no cloud.
