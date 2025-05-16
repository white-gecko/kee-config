from pykeepass import PyKeePass
from loguru import logger
import tomllib
from os.path import expanduser, expandvars
import os

import click


@click.command()
@click.option(
    "--keepass-file", "-f", envvar="KEEPASS_FILE", help="The keepass file (.kdbx)."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    envvar="KEEPASS_PASSWORD",
    help="The password to decrypt the keepass file.",
)
@click.option(
    "--key-file",
    "-k",
    envvar="KEEPASS_KEY_FILE",
    default=None,
    help="If a key file is required to decrypt the keepass file, specify it with this option.",
)
@click.option(
    "env_flag",
    "--env",
    "-e",
    is_flag=True,
    help="Process entries tagged as init and env and output sourcable variable assignments.",
)
@click.option(
    "export_flag",
    "--export",
    is_flag=True,
    help="Process entries tagged as init and export the secrets to the respective locations.",
)
@click.option(
    "connections_flag",
    "--connections",
    is_flag=True,
    help="Process entries tagged as init export connections to the network manager connections directory.",
)
@click.option(
    "--system-connections",
    envvar="NM_SYSTEM_CONNECTIONS",
    default="/etc/NetworkManager/system-connections",
    help="The directory of the network-manager system connections",
)
def cli(
    keepass_file,
    password,
    key_file,
    env_flag,
    export_flag,
    connections_flag,
    system_connections,
):
    """Read config from a keepass file."""

    # load database
    kp = PyKeePass(keepass_file, password=password, keyfile=key_file)

    # find any entry by its title
    tags = ["init"]
    if env_flag:
        tags += "env"
    entries = kp.find_entries(tags=tags)
    logger.debug("hi")
    for entry in entries:
        # TODO, make sure it was not deleted or is in the trash
        logger.info(f"Processing init entry: {entry.title}")
        init_config_string = entry.get_custom_property("init")
        init_config = tomllib.loads(init_config_string)
        logger.debug(f"Init config: {init_config}")

        if env_flag:
            logger.debug("hi")
            process_section(entry, init_config, "env", kee_env)

        if export_flag:
            process_section(entry, init_config, "files", write_attachment)

        if connections_flag:
            process_section(entry, init_config, "connections", write_connection)


def process_section(entry, init_config, section, method):
    """From an entry process the subsections of a specified toml section with the given method."""
    if section in init_config:
        for config_section, config in init_config[section].items():
            logger.info(f"Processing {section} init block: {config_section}")
            method(entry, **config)


def kee_env(entry, **env):
    """Get variables from the keepass file and write them to stdout to be evaluated.
    E.g. with `> eval $(kee-config --env)`"""
    for key, value in env.items():
        print(f'export {key}="{value}"')


def write_attachment(entry, attachment, target, mode):
    """Write an attachment from the keepass file to the filesystem."""
    # Alternatively get it from entry.attachments
    kee_attachment = kp.find_attachments(
        element=entry, filename=attachment, first=True, recursive=False
    )
    if not kee_attachment:
        logger.error(f"attachment {attachment} could not be found.")
        return
    target_path = expanduser(expandvars(target))
    target_descriptor = os.open(
        path=target_path,
        flags=(
            os.O_WRONLY  # access mode: write only
            | os.O_CREAT  # create if not exists
        ),
        mode=int(mode, 8),
    )
    # TODO create parents
    with open(target_descriptor, mode="wb") as target_file:
        target_file.write(kee_attachment.binary)


def export_connection(
    entry,
):
    """Write a network manager connection from the keepass file to the network manager system-connections in filesystem."""
    # nmcli --offline connection add type ethernet con-name Example-Connection ipv4.addresses 192.0.2.1/24 ipv4.dns 192.0.2.200 ipv4.method manual > /etc/NetworkManager/system-connections/example.nmconnection
    # chown root:root
    # chmod 600
    # nmcli connection reload
    pass


def import_connections():
    """Get the connections (mostly wifi) from the system to store them in the keepass file."""
    # nmcli connection show
    # List system_connections
    "This is just a stub, first we need to be able to write them"

    pass


if __name__ == "__main__":
    cli()
