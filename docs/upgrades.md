# Upgrade and rollback

Read release notes and back up state before every version change. Stable
releases will document schema and configuration compatibility.

1. Record the running image digest or binary version.
2. Back up SQLite consistently and verify the master key is retrievable from
   the secret manager without exposing it.
3. Run `llmap config check` with the new binary against a copy of configuration.
4. Start the new version on a canary port with a restored database copy.
5. Exercise login, redacted account listing, one non-stream and one streaming
   synthetic request, pause/resume, metrics, and optional forward mode.
6. Drain new requests at the ingress, stop the old process, start the new one,
   and watch classified outcomes.

For rollback, stop the new process and restore the old binary plus the database
backup if the release performed a non-backward-compatible migration. Never run
two versions against the same SQLite files. Credential, master-key, and CA
rotations are separate operational events and should not be hidden inside a
routine software upgrade.
