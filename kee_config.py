from pykeepass import PyKeePass
from loguru import logger
import tomllib
from os.path import expanduser, expandvars
import os

import click

@click.command()
@click.option('--keepass-file', '-f', envvar="KEEPASS_FILE", help='The keepass file (.kdbx).')
@click.option(
    "--password", prompt=True, hide_input=True, envvar="KEEPASS_PASSWORD", help='The password to decrypt the keepass file.'
)
@click.option('--key-file', '-k', envvar="KEEPASS_KEY_FILE", default=None, help='If a key file is required to decrypt the keepass file, specify it with this option.')
def cli(keepass_file, password, key_file):
    """Read config from a keepass file."""

    # load database
    kp = PyKeePass(keepass_file, password=password, keyfile=key_file)

    # find any entry by its title
    entries = kp.find_entries(tags='init')
    for entry in entries:
        # TODO, make sure it was not deleted or is in the trash
        logger.info(f"Processing init entry: {entry.title}")
        init_config_string = entry.get_custom_property("init")
        init_config = tomllib.loads(init_config_string)
        logger.debug(f"Init config: {init_config}")
        for config_section, config in init_config.items():
            logger.info(f"Processing init property: {config_section}")
            # Alternatively get it from entry.attachments
            attachment = kp.find_attachments(element=entry, filename=config["attachment"], first=True, recursive=False)
            if not attachment:
                logger.error(f"attachment {config["attachment"]} could not be found.")
                continue
            target_path = expanduser(expandvars(config["target"]))
            target_descriptor = os.open(
                path=target_path,
                flags=(
                    os.O_WRONLY  # access mode: write only
                    | os.O_CREAT  # create if not exists
                ),
                mode=int(config["mode"], 8)
            )
            with open(target_descriptor, mode="wb") as target_file:
                target_file.write(attachment.binary)

def store_wifis(system_connections):
    pass


if __name__ == '__main__':
    cli()
