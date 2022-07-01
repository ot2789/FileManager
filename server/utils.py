# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import random
import string
import os
from datetime import datetime

STRING_LENGTH = 8


class SingletonMeta(type):
    """Meta class for singletons.

    """

    def __call__(cls, **kwargs):
        pass


def generate_string() -> str:
    """Generate random string.

    Method generates random string with digits and latin letters.

    Returns:
        str: random string.

    """

    pass


def convert_date(timestamp: float) -> str:
    """Convert date from timestamp to string.

    Example of date format: 2019-09-05 11:22:33.

    Args:
        timestamp (float): date timestamp.

    Returns:
        str: converted date.

    """

    pass


def get_metadata(file_path: str) -> dict:
    """Get file metadata

    Args:
        file_path (string) : File from which we get the metadata

    Returns:
        Dict, which contains full info about file. Keys:
            name (str): name of file with .txt extension.
            create_date (str): date of file creation. (nicely formatted)
            edit_date (str): date of last file modification. (nicely formatted)
            size (int): size of file in bytes.
    """

    pass
