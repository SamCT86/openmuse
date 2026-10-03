import json

from openmuse.checkpoint_conformance import run_conformance


def test_checkpoint_publisher_conformance_harness():
    report = run_conformance()

    assert report["canonical_body"] is True
    assert report["digest_matches"] is True
    assert report["overwrite_rejected"] is True
    assert report["redirect_rejected"] is True
    assert report["non_success_rejected"] is True
    assert report["query_secret_absent_from_logs"] is True

    receipt = report["receipt"]
    assert receipt["status"] == 201
    assert receipt["sha256"]
    assert receipt["version"] == f'"{receipt["sha256"]}"'


def test_conformance_evidence_never_contains_presigned_query_secret():
    report = run_conformance()
    serialized = json.dumps(report, sort_keys=True)

    assert "conformance-query-secret" not in serialized
    assert all("?" not in event["path"] for event in report["events"])


def test_overwrite_attempt_is_observable_without_mutating_first_object():
    report = run_conformance()
    puts = [event for event in report["events"] if event["kind"] == "put"]

    assert len(puts) == 2
    assert puts[0]["path"] == "/objects/checkpoint.json"
    assert puts[1]["path"] == "/objects/checkpoint.json"
    assert puts[0]["body_sha256"] == puts[1]["body_sha256"]
