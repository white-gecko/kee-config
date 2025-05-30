from pykeepass import PyKeePass
from loguru import logger
import tomllib
from os.path import expanduser, expandvars
from pathlib import Path
import os
import subprocess
import json

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
    "json_flag",
    "--json",
    is_flag=True,
    help="Retun the export variables as JSON string, e.g. to read it with fromJSON in a Taskfile.",
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
    json_flag,
    export_flag,
    connections_flag,
    system_connections,
):
    """Read config from a keepass file."""
    if system_connections:
        system_connections = Path(system_connections)
    kc = KeeConfig(
        keepass_file,
        password=password,
        keyfile=key_file,
        system_connections=system_connections,
    )
    kc.load(
        env_flag=env_flag,
        json_flag=json_flag,
        export_flag=export_flag,
        connections_flag=connections_flag,
    )


class KeeConfig:
    def __init__(
        self,
        keepass_file,
        password,
        keyfile=None,
        system_connections: Path = Path("/etc/NetworkManager/system-connections"),
    ):
        # load database
        self.kp = PyKeePass(keepass_file, password=password, keyfile=keyfile)
        self.system_connections = system_connections

    def load(
        self,
        env_flag: bool = False,
        json_flag: bool = False,
        export_flag: bool = False,
        connections_flag: bool = False,
    ):
        # find any entry by its title
        tags = ["init"]
        if env_flag:
            tags += "env"
            self.json_flag = json_flag
        entries = self.kp.find_entries(tags=tags)

        if env_flag:
            self.kee_env(entries)

        for entry in entries:
            if export_flag:
                self.process_section(entry, "files", self.export_attachment)

            if connections_flag:
                self.process_section(entry, "connections", self.export_connection)

    def process_init_config(self, entry):
        # TODO, make sure it was not deleted or is in the trash
        logger.info(f"Processing init entry: {entry.title}")
        init_config_string = entry.get_custom_property("init")
        if init_config_string:
            return tomllib.loads(init_config_string)

    def process_section(self, entry, section, method):
        """From an entry process the subsections of a specified toml section with the given method."""

        init_config = self.process_init_config(entry)
        logger.debug(f"Init config: {init_config}")

        if init_config and section in init_config:
            for config_section, config in init_config[section].items():
                logger.info(f"Processing {section} init block: {config_section}")
                method(entry, **config)
        else:
            method(entry)

    def kee_env(self, entries):
        """Get variables from the keepass file and write them to stdout to be evaluated.
        E.g. with `> eval $(kee-config --env)`

        entry: is the keepass entry
        env: is a dictionary parsed from the "init" get_custom_property of the entry
        """
        env = {}
        for entry in entries:
            init_config = self.process_init_config(entry)
            if (not init_config or not "env" in init_config) and "env" in entry.tags:
                env[entry.username] = entry.password
            else:
                env |= init_config["env"]
        logger.debug(f"JSON flag is: {self.json_flag}")
        if self.json_flag:
            print(json.dumps(env))
        else:
            print_export(env)

    def export_attachment(
        self, entry, attachment: str = None, target: str = None, mode: str = None
    ):
        """Write an attachment from the keepass file to the filesystem."""
        if not attachment:
            return
        # Alternatively get it from entry.attachments
        kee_attachment = self.kp.find_attachments(
            element=entry, filename=attachment, first=True, recursive=False
        )
        if not kee_attachment:
            logger.error(f"attachment {attachment} could not be found.")
            return
        target_path = Path(expanduser(expandvars(target)))
        write_file_with_permissions(
            target_path, kee_attachment.binary, permissions=mode
        )

    def export_connection(self, entry, **config):
        """Write a network manager connection from the keepass file to the network manager system-connections in filesystem."""
        logger.debug(f"export_connection: {entry.title}")
        connection_type = None
        if not config:
            connection_types = set(entry.tags).intersection(
                ["ethernet", "wifi", "vpn", "wireguard"]
            )
            if len(connection_types) != 1:
                logger.warning(f"Cannot identify connection type from tags: {entry.tags}")
                return
            connection_type = next(iter(connection_types))
        connection_type = config.get("type", connection_type)
        connection_name = config.get("con-name", entry.title)
        system_connection_file = (
            self.system_connections / f"{connection_name}.nmconnection"
        )
        if connection_type == "ethernet":
            # not yet implemented
            # command_args = [
            #     "ipv4.addresses",
            #     "192.0.2.1/24",
            #     "ipv4.dns",
            #     "192.0.2.200",
            #     "ipv4.method",
            #     "manual",
            # ]
            command_args = []
        elif connection_type == "wifi":
            command_args = [
                "ssid",
                config.get("ssid", entry.username),
                "wifi-sec.key-mgmt",
                config.get("wifi-sec", {}).get("key-mgmt", "wpa-psk"),
                "wifi-sec.psk",
                config.get("wifi-sec", {}).get("psk", entry.password),
            ]
            logger.debug(f"connection_name: {connection_name}")
        else:
            logger.error(f"Unsupported type {connection_type}")
            return
        command = [
            "nmcli",
            "--offline",
            "connection",
            "add",
            "type",
            connection_type,
            "con-name",
            connection_name,
            *command_args,
        ]
        complete = subprocess.run(command, capture_output=True)
        if complete.returncode == 0:
            write_file_with_permissions(
                system_connection_file, complete.stdout, permissions="600", chown=(0, 0)
            )
            # nmcli connection reload
        else:
            logger.error(
                f"Standard output: {complete.stdout}, Error output: {complete.stderr}",
            )

    def import_connections(self):
        """Get the connections (mostly wifi) from the system to store them in the keepass file."""
        # nmcli connection show
        # List system_connections
        logger.info("This method is not yet implemented")


def print_export(dictionry):
    for key, value in dictionry.items():
        print(f'export {key}="{value}"')


def write_file_with_permissions(
    path: Path,
    data: str | bytes,
    permissions: str | None = None,
    chown: tuple[int, int] | None = None,
    mode: str | None = "wb",
):
    path.parent.mkdir(parents=True, exist_ok=True)
    """Create a target descriptor with:
    the path, the flags O_WRONLY: "access mode: write only" and O_CREAT: "create if not exists", and
    the file mode/file permissions wich are read from an ocatal (base 8) number.
    """
    if permissions:
        descriptor = os.open(
            path=path,
            flags=(os.O_WRONLY | os.O_CREAT),
            mode=int(permissions, 8),
        )
    else:
        descriptor = path
    with open(descriptor, mode="wb") as file:
        file.write(data)
    if chown:
        try:
            os.chown(path, chown[0], chown[1])
        except PermissionError as e:
            logger.error(f"Can't set the file permissions to {chown} for {path}: {e}")


if __name__ == "__main__":
    cli()
