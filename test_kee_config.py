from click.testing import CliRunner
from kee_config import cli


def test_cli_env():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["--keepass-file", "TestPasswords.kdbx", "--password", "start123", "--env"]
    )
    assert result.exit_code == 0
    assert result.output == 'export SECRET="super secret"\n'


def test_cli_export():
    pass


def test_connectio():
    pass
