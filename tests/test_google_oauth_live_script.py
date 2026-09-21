from pathlib import Path


def test_live_harness_is_opt_in_and_uses_no_persistent_token_path():
    source=(Path(__file__).parents[1]/"scripts/google_oauth_live.py").read_text()
    assert "TemporaryDirectory" in source
    assert "manager.revoke_and_delete()" in source
    assert "post-revoke operation did not fail closed" in source
    workflow=(Path(__file__).parents[1]/".github/workflows/google-oauth-disposable.yml").read_text()
    assert "workflow_dispatch" in workflow
    assert "pull_request" not in workflow
