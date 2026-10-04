import os
from pathlib import Path

import pytest

from flowsec import config


def test_never_reads_env_from_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A scanned repo with a planted .env must not leak into FlowSec's environment.
    (tmp_path / ".env").write_text("FLOWSEC_PLANTED=evil\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FLOWSEC_PLANTED", raising=False)
    monkeypatch.delenv("FLOWSEC_ENV_FILE", raising=False)
    monkeypatch.setattr(config, "USER_ENV_FILE", tmp_path / "no-such-dir" / ".env")

    assert config.load_user_env() is None
    assert "FLOWSEC_PLANTED" not in os.environ


def test_loads_explicit_env_file_without_overriding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "tokens.env"
    env_file.write_text("FLOWSEC_TEST_TOKEN=from-file\nFLOWSEC_TEST_KEEP=from-file\n")
    monkeypatch.delenv("FLOWSEC_TEST_TOKEN", raising=False)
    monkeypatch.setenv("FLOWSEC_TEST_KEEP", "from-shell")

    assert config.load_user_env(str(env_file)) == env_file
    assert os.environ["FLOWSEC_TEST_TOKEN"] == "from-file"
    assert os.environ["FLOWSEC_TEST_KEEP"] == "from-shell"
    monkeypatch.delenv("FLOWSEC_TEST_TOKEN", raising=False)
