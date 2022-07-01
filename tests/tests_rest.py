# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import shutil
import pytest
import json
import logging
import server.utils as utils
from datetime import datetime, timedelta
import server.config
from aiohttp import web, ClientResponse
from server.handler import Handler
# from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher
from server.file_service import FileService, FileServiceSigned
import functools
import itertools

# Logging will present extra information when running pytest
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

EXTENSION_TXT = 'txt'
TEST_FOLDER = os.path.abspath('../storage')
TEST_USER_ID = 1
TEST_FILES_PART_NAME = ['beefDead', '12345678', 'testFile', 'catMouse']
TEST_FILES_SECURITY = ['low', 'medium', 'low', 'high']
TEST_FILES_SIGNED = [False, False, True, True]
TEST_FILES_NAMES = [f'{f}_{s}.{EXTENSION_TXT}' for f, s in zip(TEST_FILES_PART_NAME, TEST_FILES_SECURITY)]
TEST_FILES_CONTENTS = ['lmao', 'test1', 'test2', 'ABC']
TEST_FILE_NO_EXIST = "notExist_low.txt"


def create_and_move_to_test_folder():
    if not os.path.exists(TEST_FOLDER):
        os.mkdir(TEST_FOLDER)
    fs = FileService(path=TEST_FOLDER)
    fss = FileServiceSigned(path=TEST_FOLDER)
    fs.path = TEST_FOLDER
    fss.path = TEST_FOLDER
    os.chdir(TEST_FOLDER)


def get_files_by_extension(directory, extension):
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    files = list([f for f in files if len(f.split('.')) > 1 and f.split('.')[-1] == extension])
    return files


def create_test_files():
    for file_name, security, sign, content in \
            zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):
        full_path = os.path.join(os.getcwd(), file_name)
        with open(full_path, 'wb') as file_handler:
            data = bytes(content, 'utf-8')
            if security == 'low':
                file_handler.write(data)
            if security == 'medium':
                cipher = AESCipher(TEST_FOLDER)
                cipher.write_cipher_text(data, file_handler, file_name.split('.')[0])
            elif security == 'high':
                cipher = RSACipher(TEST_FOLDER, TEST_USER_ID)
                cipher.write_cipher_text(data, file_handler, file_name.split('.')[0])

        if sign:
            sig_path = full_path.replace('.txt', '.md5')
            sig = os.path.basename(full_path) + '_' + \
                utils.convert_date(os.path.getctime(full_path)) + '_' + \
                str(os.path.getsize(full_path)) + '_' + \
                content
            sig = HashAPI.hash_md5(sig)
            with open(sig_path, 'wb') as file_handler:
                data = bytes(sig, 'utf-8')
                file_handler.write(data)


@pytest.fixture
def client(loop, aiohttp_client):
    handler = Handler(TEST_FOLDER)
    app = web.Application()
    app.add_routes([
        web.get('/', handler.handle),
        web.get('/files/list', handler.get_files),
        web.get('/files', handler.get_file_info),
        web.post('/files', handler.create_file),
        web.delete('/files/{filename}', handler.delete_file),
        web.post('/change_file_dir', handler.change_file_dir),
    ])

    return loop.run_until_complete(aiohttp_client(app))


def cleanup():
    os.chdir(TEST_FOLDER)
    for file in os.listdir(TEST_FOLDER):
        file_path = os.path.join(TEST_FOLDER, file)

        if os.path.isfile(file_path):
            os.remove(file_path)
        else:
            shutil.rmtree(file_path)


@pytest.fixture(scope='function')
def prepare_data(request):
    cleanup()
    create_and_move_to_test_folder()
    create_test_files()
    yield
    cleanup()


async def check_response(resp: ClientResponse, code: int, json_status: str = None):
    assert resp.status == code
    try:
        text = await resp.text()
        result = json.loads(text)
    except Exception:
        result = {}
    if json_status is not None:
        assert result.get('status') == json_status
    return result


class TestSuite:
    async def test_connection(self, client):
        location = '/'

        logger.info(f'Test PUT "{location}" - Method not allowed')
        resp = await client.put(location)
        await check_response(resp, 405)

        logger.info(f'Test GET "{location}" - Method allowed')
        resp = await client.get(location)
        result = await check_response(resp, 200, 'success')
        logger.info('Test success')

    async def test_get_files(self, client, prepare_data):
        location = '/files/list'

        logger.info(f'Test GET "{location}" - Get files')
        resp = await client.get(location)
        result = await check_response(resp, 200, 'success')

        assert len(result.get('data')) == len(TEST_FILES_PART_NAME)
        for md in result.get('data'):
            name = md.get('name')
            assert name in TEST_FILES_NAMES, f'File "{name}" not found in list.'

        logger.info('Test success')

    async def test_get_file_info(self, client, prepare_data):
        format_location = '/files?filename={}&is_signed={}&user_id={}'

        for file_name, security, sign, content in \
                zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):

            location = format_location.format(
                file_name.replace('.' + EXTENSION_TXT, ''),
                'true' if sign else 'false',
                TEST_USER_ID)
            logger.info(f'Test GET "{location}" - Get file info')
            resp = await client.get(location)
            result = await check_response(resp, 200, 'success')
            assert result.get('data').get('content') == content
            logger.info('Test success')

    async def test_create_delete_file(self, client, prepare_data):
        location = "/files"
        data = {
            'content': "blabla",
            'security_level': "high",
            'user_id': TEST_USER_ID,
            'is_signed': True,
        }

        logger.info(f'Test POST "{location}"')
        resp = await client.post('/files', json=data)
        result = await check_response(resp, 200, 'success')
        assert result.get('data').get('content') == data['content']
        name = result.get('data').get('name').replace('.' + EXTENSION_TXT, '')

        resp = await client.get('/files/list')
        result = await check_response(resp, 200, 'success')

        assert len(result.get('data')) == len(TEST_FILES_PART_NAME) + 1

        resp = await client.delete(f'/files/{name}')
        result = await check_response(resp, 200, 'success')

        resp = await client.get('/files/list')
        result = await check_response(resp, 200, 'success')

        assert len(result.get('data')) == len(TEST_FILES_PART_NAME)

        logger.info('Test success')

    async def test_neg_wrong_method(self, client):
        methods = {
            'get': ('/', '/files/list', '/files',),
            'post': ('/files', '/change_file_dir',),
            # We add '/files/list' here because it may be confused by a file
            'delete': (f'/files/{TEST_FILE_NO_EXIST}', '/files/list'),
        }
        locations = set(functools.reduce(lambda a, b: a+b, methods.values()))
        for loc in sorted(locations):
            unsupported_methods = list(methods.keys())
            for m in methods:
                if loc in methods[m]:
                    unsupported_methods.remove(m)

            logger.info(f'Test UNSUPPORTED {unsupported_methods} for "{loc}"')
            for m in unsupported_methods:
                meth_call = getattr(client, m)
                resp = await meth_call(loc)
                await check_response(resp, 405)
            logger.info('Test success')


    async def test_neg_get_file_info_missing_fields(self, client, prepare_data):
        general_location = '/files?'
        location_parts = ('filename', 'is_signed', 'user_id')

        for combo in itertools.combinations(location_parts, 2):
            format_location = general_location
            for part in combo:
                if format_location[-1] != '?':
                    format_location += '&'
                format_location += part + '=' + f'{{{part}}}'
            for file_name, security, sign, content in \
                    zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):

                location = format_location.format(
                    filename=file_name.replace('.' + EXTENSION_TXT, ''),
                    is_signed='true' if sign else 'false',
                    user_id=TEST_USER_ID
                )

                logger.info(f'Test GET "{location}" - Get file info incomplete')
                resp = await client.get(location)
                if 'is_signed' not in format_location:
                    await check_response(resp, 400, 'error')
                else:
                    if 'user_id' not in format_location:
                        if security == 'high':
                            await check_response(resp, 400, 'error')
                        else:
                            result = await check_response(resp, 200, 'success')
                            assert result.get('data').get('content') == content
                    else:
                        await check_response(resp, 400, 'error')

                logger.info('Test success')

    async def test_neg_get_file_info_incorrect_names(self, client, prepare_data):
        format_location = '/files?filename={}&is_signed={}&user_id={}'

        for alter_var in ('sign', 'security',):
            for file_name, security, sign, content in \
                    zip(TEST_FILES_PART_NAME, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):

                if alter_var == 'sign':
                    if not sign:
                        sign = True
                    else:
                        # Skip the test for altered sign
                        # We are unable to detect if the signature is missing
                        continue
                elif alter_var == 'security':
                    security_list = ('low', 'medium', 'high',)
                    # Move security to the right
                    security = security_list[(security_list.index(security) + 1) % len(security_list)]
                else:
                    assert False, 'Alter variable unhandled!'
                file_name = f'{file_name}_{security}'

                location = format_location.format(
                    file_name.replace('.' + EXTENSION_TXT, ''),
                    'true' if sign else 'false',
                    TEST_USER_ID)
                logger.info(f'Test GET "{location}" - Get file info incorrect request for "{alter_var}"')
                resp = await client.get(location)
                await check_response(resp, 400, 'error')
                logger.info('Test success')
