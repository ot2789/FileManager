# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import argparse
import os
import sys
import logging
import json
from aiohttp import web
import server.config
from server.handler import Handler
from server.database import DataBase
import server.file_service_no_class as FileServiceNoClass
from server.file_service import FileService, FileServiceSigned


def commandline_parser():
    """Command line parser.

    Parse port and working directory parameters from command line.

    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', '--folder', default=os.getcwd(),
        help='working directory (absolute or relative path, default: current app folder FileServer)'
    )
    parser.add_argument(
        '-p', '--port', default='8080', help='port (default: 8080)'
    )
    parser.add_argument(
        '-i', '--init', action='store_true', default=0, help='Erase and initialize database'
    )
    return parser


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

    print('Input filename (without extension):')
    filename = input()
    print('Check signature? y/n (default: n)')
    check_sig = input().lower().strip() or 'n'

    file_service = FileService()
    if check_sig == 'y':
        file_service = FileServiceSigned()

    data = file_service.get_file_data(filename, 1)

    return data


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

    print('Input content:')
    content = input()
    print('Input security:')
    security_level = input()
    print('Sign file? y/n (default: n)')
    create_sig = input().lower().strip() or 'n'

    file_service = FileService()
    if create_sig == 'y':
        file_service = FileServiceSigned()

    data = file_service.create_file(content, security_level, 1)

    return data


def delete_file():
    """Delete file.

    Returns:
        Str with filename with .txt file extension.

    Raises:
        AssertionError: if file does not exist.

    """

    print('Input filename (without extension):')
    filename = input()

    data = FileService().delete_file(filename)

    return data


def change_dir():
    """Change working directory.

    Returns:
        True (errors handle incorrect cases)

    """

    print('Input new working directory path:')
    new_path = input()

    FileService().path = new_path
    FileServiceSigned().path = new_path

    return True


def main_console():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -h --help - help.

    """

    parser = commandline_parser()
    namespace = parser.parse_args(sys.argv[1:])
    path = namespace.folder
    FileService(path=path)
    FileServiceSigned(path=path)

    print('Commands:')
    print('list - get files list')
    print('get - get file data')
    print('create - create file')
    print('delete - delete file')
    print('chdir - change working directory')
    print('exit - exit from app')
    print('\n')

    while True:

        try:
            print('Input command:')
            command = input().strip()

            if command == 'list':
                data = FileService().get_files()

            elif command == 'get':
                data = get_file_data()

            elif command == 'create':
                data = create_file()

            elif command == 'delete':
                data = delete_file()

            elif command == 'chdir':
                data = change_dir()

            elif command == 'exit':
                return

            else:
                raise ValueError('Invalid command')

            output = {
                'status': 'success',
                'result': data,
            }
        except (ValueError, AssertionError) as err:
            output = {
                'status': 'error',
                'result': str(err),
            }

        if output:
            print(f'\n{json.dumps(output, indent=4)}\n')


def main():
    """Entry point of app.

    Get and parse command line parameters and configure web app.
    Command line options:
    -f --folder - working directory (absolute or relative path, default: current app folder FileServer).
    -p --port - port of the server (default: 8080).
    -h --help - help.

    """

    parser = commandline_parser()
    namespace = parser.parse_args(sys.argv[1:])
    path = namespace.folder
    FileService(path=path)
    FileServiceSigned(path=path)
    db = DataBase()

    if namespace.init:
        db.init_system()

    handler = Handler(namespace.folder)
    app = web.Application()
    app.add_routes([
        web.get('/', handler.handle),
        web.get('/files/list', handler.get_files),
        web.get('/files', handler.get_file_info),
        web.post('/files', handler.create_file),
        web.delete('/files/{filename}', handler.delete_file),
        web.post('/change_file_dir', handler.change_file_dir),
        web.post('/signup', handler.signup),
        web.post('/signin', handler.signin),
        web.get('/logout', handler.logout),
        web.get('/files/download', handler.download_file),
        web.get('/files/download/queued', handler.download_file_queued),
    ])
    logging.basicConfig(level=logging.INFO)
    web.run_app(app, port=namespace.port)


if __name__ == '__main__':
    main()
