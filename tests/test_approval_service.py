import pytest

from openmuse.approval_service import ApprovalService
from openmuse.models import Action


def test_persistent_exact_diff_and_single_decision(tmp_path):
    now=[100]; service=ApprovalService(tmp_path/"a.db",b"k",clock=lambda:now[0]); request,session=service.create(Action("send",{"to":"sam","body":"hi"}),"me","sam")
    assert '"body": "hi"' in request.action_json
    assert service.decide(request.id,session,"approved").status=="approved"
    with pytest.raises(ValueError,match="already"): service.decide(request.id,session,"denied")

def test_bad_session_and_expiry_fail_closed(tmp_path):
    now=[100]; service=ApprovalService(tmp_path/"a.db",b"k",clock=lambda:now[0]); request,session=service.create(Action("x",{}),"me","x",1)
    with pytest.raises(ValueError,match="session"): service.decide(request.id,"bad","approved")
    now[0]=101
    with pytest.raises(ValueError,match="expired"): service.decide(request.id,session,"approved")
