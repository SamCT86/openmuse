# Disposable Google OAuth lifecycle test

This opt-in test uses a disposable account, never a maintainer's personal account. Configure the `disposable-google-oauth` GitHub environment with `OPENMUSE_GOOGLE_CLIENT_ID`, `OPENMUSE_GOOGLE_CLIENT_SECRET`, and `OPENMUSE_GOOGLE_REDIRECT_URI`. Protect the environment and never put an authorization code or token in an issue, log, fixture, or repository secret after use.

1. Locally set the same three values and run `python scripts/google_oauth_live.py --print-authorization-url`.
2. Open the URL with the disposable account and grant only Gmail read-only and Calendar read-only.
3. Copy the one-time returned code directly into the manual workflow input.
4. The workflow exchanges the code, performs bounded reads, forces refresh, revokes at Google, deletes its temporary encrypted record, and proves all post-revoke access fails closed.
5. Delete the disposable account and rotate the OAuth client secret after a testing campaign.

If account creation requires a real phone number or device verification, stop. Do not bypass verification or use a contributor's personal identity. The workflow is not a normal pull-request check because live credentials and consent must never be available to untrusted code.
