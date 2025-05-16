from click.testing import CliRunner
from kee_config import cli
import os

TEST_FILE = "TestPasswords.kdbx"
TEST_FILE_PWD = "start123"


def test_cli_env():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--keepass-file", TEST_FILE, "--password", TEST_FILE_PWD, "--env"]
    )
    assert result.exit_code == 0
    assert result.output == 'export SECRET="super secret"\n'


def test_cli_export():
    os.environ["HOME"] = "/tmp/bla"
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--keepass-file", TEST_FILE, "--password", TEST_FILE_PWD, "--export"]
    )

    assert result.exit_code == 0


def test_cli_connection():
    pass
