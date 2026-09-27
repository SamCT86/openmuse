import sys

import pytest

from openmuse.bounded_process import run_bounded


def test_real_child_is_capped_before_memory_capture():
    with pytest.raises(ValueError, match="output limit"):
        run_bounded([sys.executable, "-c", "print('x'*2000000)"], "", 1024, 5)


def test_real_child_timeout():
    with pytest.raises(TimeoutError, match="timed out"):
        run_bounded([sys.executable, "-c", "import time; time.sleep(5)"], "", 1024, 0.05)


def test_normal_json_output():
    result = run_bounded([sys.executable, "-c", "print('{\"ok\":true}')"], "", 1024, 5)
    assert result.stdout.strip() == '{"ok":true}'
