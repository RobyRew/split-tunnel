# Authorised keys

One `.pub` file per person, e.g. `alice.pub`, `bob.pub`.

```bash
# each person generates their own — NEVER share a private key
ssh-keygen -t ed25519 -C "alice"
# they send you ONLY the .pub, you drop it here, then:
docker compose restart
```

**Revoking one person** — delete their file and restart. Nobody else is
affected, and the SSH log records which key fingerprint each session used, so
sessions remain attributable to a person.

Files here are ignored by git so you never publish someone's key by accident.
