# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
import json
# from aiohttp import web
import server.config
# from server.handler import Handler
# from server.database import DataBase
import server.file_service_no_class as FileServiceNoClass
# from server.file_service import FileService, FileServiceSigned


def commandline_parser():
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    pass


def get_file_data():
    """Get full info about file.

    Returns:
        Dict, which contains full info about file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            edit_date (str): date of last file modification.
            size (int): size of file in bytes.

    Raises:
        AssertionError: if file does not exist, filename format is invalid,
        ValueError: if security level is invalid.

    """

    pass


def create_file():
    """Create new .txt file.

    Method generates name of file from random string with digits and latin letters.

    Returns:
        Dict, which contains name of created file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            size (int): size of file in bytes,
            user_id (int): user Id.

    Raises:
        AssertionError: if user_id is not set,
        ValueError: if security level is invalid.

    """

    pass


def delete_file():
    """Delete file.

    Returns:
        Str with filename with .txt file extension.

    Raises:
        AssertionError: if file does not exist.

    """

    pass


def change_dir():
    """Change working directory.

    Returns:
        True (errors handle incorrect cases)

    """

    pass


def main():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -h --help - help.

    """

    pass


if __name__ == '__main__':
    main()
