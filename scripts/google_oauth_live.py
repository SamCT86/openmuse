"""Opt-in disposable-account Google OAuth lifecycle check.

The operator completes consent in a browser and passes the returned code. This
script stores tokens only in a temporary encrypted vault, reads Gmail and
Calendar, forces refresh, revokes at Google, and proves post-revoke failure.
"""
from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from pathlib import Path

from openmuse.google_calendar_connector import GOOGLE_CALENDAR_READONLY_SCOPE, GoogleCalendarConnector
from openmuse.google_mail_connector import GOOGLE_MAIL_READONLY_SCOPE, GoogleMailConnector
from openmuse.google_oauth import GoogleOAuthManager
from openmuse.secrets import SecretVault


def required(name: str) -> str:
    value=os.environ.get(name,"")
    if not value: raise SystemExit(f"missing required environment variable: {name}")
    return value


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--authorization-code"); p.add_argument("--print-authorization-url",action="store_true"); a=p.parse_args()
    scopes={GOOGLE_MAIL_READONLY_SCOPE,GOOGLE_CALENDAR_READONLY_SCOPE}
    with tempfile.TemporaryDirectory() as directory:
        vault=SecretVault(Path(directory)/"oauth.vault",secrets.token_bytes(32))
        manager=GoogleOAuthManager(required("OPENMUSE_GOOGLE_CLIENT_ID"),required("OPENMUSE_GOOGLE_CLIENT_SECRET"),required("OPENMUSE_GOOGLE_REDIRECT_URI"),scopes,vault)
        if a.print_authorization_url:
            print(manager.authorization_url(secrets.token_urlsafe(24))); return
        if not a.authorization_code: raise SystemExit("pass --authorization-code from the disposable account consent redirect")
        manager.exchange_code(a.authorization_code)
        mail=GoogleMailConnector(manager.access_token); calendar=GoogleCalendarConnector(manager.access_token)
        mail.invoke("list_messages",{"max_results":1}); calendar.invoke("list_events",{"max_results":1})
        manager._clock=lambda: 10**20  # force the public access_token path to refresh
        manager.access_token()
        manager.revoke_and_delete(); mail.delete_cached_data(); calendar.delete_cached_data()
        for operation in (manager.access_token, lambda: mail.invoke("list_messages",{"max_results":1}), lambda: calendar.invoke("list_events",{"max_results":1})):
            try: operation()
            except ValueError: pass
            else: raise AssertionError("post-revoke operation did not fail closed")
        print("PASS: auth, Gmail read, Calendar read, refresh, revoke, and post-revoke fail-closed")
if __name__=="__main__": main()
