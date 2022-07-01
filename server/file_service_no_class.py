# Copyright 2019 by Kirill Kanin.
# All rights reserved.


import os
import sys
import server.utils as utils

EXTENSION = 'txt'


def change_dir(path):
    """Change current directory of app.

    Args:
        path (str): Path to working directory with files.

    Raises:
        AssertionError: if directory does not exist.

    """

    assert os.path.isdir(path), f'Path "{path}" not found or not a directory.'
    os.chdir(path)


def get_file_data(filename):
    """Get full info about file.

    Args:
        filename (str): Filename without .txt file extension.

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

    basename = f'{filename}.{EXTENSION}'
    full_filename = os.path.join(os.getcwd(), basename)
    assert os.path.exists(full_filename), f'File "{basename}" does not exist'

    metadata = utils.get_metadata(full_filename)
    with open(full_filename, 'rb') as file_handler:
        metadata['content'] = file_handler.read().decode('utf-8')
    return metadata


def get_files():
    """Get info about all files in working directory.

    Returns:
        List of dicts, which contains info about each file. Keys:
            name (str): name of file with .txt extension.
            create_date (str): date of file creation.
            edit_date (str): date of last file modification.
            size (str): size of file in bytes.

    """

    workdir = os.getcwd()
    data = []
    files = [f for f in os.listdir(workdir) if os.path.isfile(os.path.join(workdir, f))]
    files = list([f for f in files if len(f.split('.')) > 1 and f.split('.')[-1] == EXTENSION])

    for file_name in files:
        file_path = os.path.join(workdir, file_name)
        data.append(utils.get_metadata(file_path))

    return data


def create_file(content=None):
    """Create new .txt file.

    Method generates name of file from random string with digits and latin letters.

    Args:
        content (str): String with file content.

    Returns:
        Dict, which contains name of created file. Keys:
            name (str): name of file with .txt extension.
            content (str): file content.
            create_date (str): date of file creation.
            size (int): size of file in bytes,

    """

    workdir = os.getcwd()

    # Retry until a new file can be created
    while 1:
        basename = f'{utils.generate_string()}.{EXTENSION}'
        file_path = os.path.join(workdir, basename)
        # When it doesn't exist we can create it
        if not os.path.exists(file_path):
            break

    with open(file_path, 'wb') as file_handler:
        if not content:
            content = ''
        data = bytes(content, 'utf-8')
        file_handler.write(data)

    metadata = utils.get_metadata(file_path)
    metadata.pop('edit_date')
    metadata['content'] = content
    return metadata


def delete_file(filename):
    """Delete file.

    Args:
        filename (str): Filename without .txt file extension.

    Returns:
        Str with filename with .txt file extension.

    Raises:
        AssertionError: if file does not exist.

    """

    workdir = os.getcwd()
    basename = f'{filename}.{EXTENSION}'
    file_path = os.path.join(workdir, basename)
    assert os.path.exists(file_path), f'File "{basename}" does not exist'

    os.remove(file_path)

    return basename
