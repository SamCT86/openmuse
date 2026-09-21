import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("typed_tool", Path(__file__).parents[1] / "examples" / "typed_tool.py")
typed_tool = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(typed_tool)
CountWords = typed_tool.CountWords
from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy


def runtime(tmp_path: Path) -> Agent:
    return Agent([CountWords()], Policy(), tmp_path / "audit.jsonl")


def test_count_words_rejects_unknown_fields_before_execution(tmp_path):
    result = runtime(tmp_path).execute(Action("count_words", {"text": "hello", "extra": True}))

    assert result.status is ActionStatus.FAILED
    assert result.error_code == "invalid_arguments"


def test_count_words_rejects_missing_text_before_execution(tmp_path):
    result = runtime(tmp_path).execute(Action("count_words", {}))

    assert result.status is ActionStatus.FAILED
    assert result.error_code == "invalid_arguments"


def test_count_words_rejects_oversized_text_before_execution(tmp_path):
    result = runtime(tmp_path).execute(Action("count_words", {"text": "x" * 1001}))

    assert result.status is ActionStatus.FAILED
    assert result.error_code == "invalid_arguments"


def test_demo_registers_tool_and_executes_end_to_end(tmp_path):
    result = typed_tool.run_demo(tmp_path / "audit.jsonl")

    assert result.status is ActionStatus.COMPLETED
    assert result.output == "4"


def test_example_main_is_runnable_without_credentials(capsys):
    exit_code = typed_tool.main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out.strip() == "completed: 4"


def test_count_words_manifest_is_read_only_closed_and_bounded():
    manifest = CountWords().manifest()

    assert manifest["risk"] == "read"
    assert manifest["schema"]["additionalProperties"] is False
    assert manifest["schema"]["required"] == ["text"]
    assert manifest["schema"]["properties"]["text"]["maxLength"] == 1000
