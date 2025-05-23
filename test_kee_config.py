from click.testing import CliRunner
from kee_config import cli
import os
import json

TEST_FILE = "TestPasswords.kdbx"
TEST_FILE_PWD = "start123"


def test_cli_env():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--keepass-file", TEST_FILE, "--password", TEST_FILE_PWD, "--env"]
    )
    output_lines = result.output.splitlines()
    assert result.exit_code == 0
    assert 'export SECRET="super secret"' in output_lines
    assert 'export INIT_VAR_PW="start123"' in output_lines
    assert 'export DELETED_VAR="does not exists"' not in output_lines


def test_cli_env_json():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--keepass-file", TEST_FILE, "--password", TEST_FILE_PWD, "--env", "--json"],
    )
    assert result.exit_code == 0
    output_dict = json.loads(result.output)
    assert "super secret" == output_dict["SECRET"]
    assert "start123" == output_dict["INIT_VAR_PW"]
    assert "DELETED_VAR" not in output_dict


def test_cli_export(tmp_path):
    os.environ["HOME"] = str(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--keepass-file", TEST_FILE, "--password", TEST_FILE_PWD, "--export"]
    )

    file = tmp_path / ".ssh" / "id_rsa_bla"
    file_pub = tmp_path / ".ssh" / "id_rsa_bla.pub"

    assert result.exit_code == 0
    # assert file.read_text(encoding="utf-8") == CONTENT
    assert len(list(tmp_path.iterdir())) == 1
    assert len(list((tmp_path / ".ssh").iterdir())) == 2
    with open(file) as file_stream:
        assert "this is some secret ssh key\n" == file_stream.read()
    with open(file_pub) as file_stream:
        assert "This is some public key\n" == file_stream.read()


def test_cli_connection():
    pass
