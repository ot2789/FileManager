# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import shutil
import pytest
import json
import logging
import math
import time
import asyncio
import server.utils as utils
from datetime import datetime, timedelta
import server.config
from aiohttp import web, ClientResponse
from server.handler import Handler
from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher
from server.file_service import FileService, FileServiceSigned
import functools
import itertools
from server.file_loader import BaseLoader

# Logging will present extra information when running pytest
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

EXTENSION_TXT = 'txt'
TEST_FOLDER = os.path.abspath('../storage')
DOWNLOAD_TEST_FOLDER = os.path.abspath('../download')
TEST_USER_ID = 1
TEST_FILES_PART_NAME = ['beefDead', '12345678', 'testFile', 'catMouse']
TEST_FILES_SECURITY = ['low', 'medium', 'low', 'high']
TEST_FILES_SIGNED = [False, False, True, True]
TEST_FILES_NAMES = [f'{f}_{s}.{EXTENSION_TXT}' for f, s in zip(TEST_FILES_PART_NAME, TEST_FILES_SECURITY)]
TEST_FILES_CONTENTS = ['lmao', 'test1', 'test2', 'ABC']
TEST_FILE_NO_EXIST = "notExist_low.txt"
TEST_USER = {
    'email': 'test@fileman.com',
    'password': '1234qwer',
    'name': 'Test',
    'surname': 'Master',
}


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


@pytest.fixture(scope="class")
def erase_db():
    db = DataBase()
    db.init_system()


@pytest.fixture(scope="class")
def change_download_loc():
    save = BaseLoader.DOWNLOAD_DIR
    BaseLoader.DOWNLOAD_DIR = DOWNLOAD_TEST_FOLDER
    yield
    BaseLoader.DOWNLOAD_DIR = save


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
        web.post('/signup', handler.signup),
        web.post('/signin', handler.signin),
        web.get('/logout', handler.logout),
        web.get('/files/download', handler.download_file),
        web.get('/files/download/queued', handler.download_file_queued),
        web.get('/users', handler.users),
        web.get('/roles', handler.roles),
        web.put('/method/{method_name}', handler.add_method),
        web.delete('/method/{method_name}', handler.delete_method),
        web.put('/role/{role_name}', handler.add_role),
        web.delete('/role/{role_name}', handler.delete_role),
        web.post('/add_method_to_role', handler.add_method_to_role),
        web.post('/delete_method_from_role', handler.delete_method_from_role),
        web.post('/change_shared_prop', handler.change_shared_prop),
        web.post('/change_user_role', handler.change_user_role),
        web.post('/change_file_dir', handler.change_file_dir),
    ])

    return loop.run_until_complete(aiohttp_client(app))


def confirm_password(user):
    user = dict(user)
    user['confirm_password'] = user['password']
    return user


def signin_info(user):
    user = dict(user)
    user.pop('name')
    user.pop('surname')
    return user


def cleanup(location):
    for file in os.listdir(location):
        file_path = os.path.join(location, file)

        if os.path.isfile(file_path):
            os.remove(file_path)
        else:
            shutil.rmtree(file_path)


@pytest.fixture(scope='function')
def prepare_data(request):
    os.chdir(TEST_FOLDER)
    cleanup(TEST_FOLDER)
    create_and_move_to_test_folder()
    create_test_files()
    yield
    cleanup(TEST_FOLDER)
    cleanup(DOWNLOAD_TEST_FOLDER)


@pytest.fixture(scope='function')
async def auth_header(client):
    loc_signup = '/signup'
    loc_signin = '/signin'
    loc_logout = '/logout'
    # This can fail!
    await client.post(loc_signup, json=confirm_password(TEST_USER))

    resp = await client.post(loc_signin, json=signin_info(TEST_USER))
    result = await check_response(resp, 200, 'success')
    header = {'Authorization': result['session_id']}
    yield header
    resp = await client.get(loc_logout, headers=header)
    await check_response(resp, 200, 'success')


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


@pytest.mark.usefixtures("erase_db", "change_download_loc")
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

    async def test_user(self, client, prepare_data):
        loc_signup = '/signup'
        loc_signin = '/signin'
        loc_logout = '/logout'
        loc_access = '/files/list'

        db = DataBase()
        db_session = DataBase().create_session()

        logger.info(f'Test sign-up')
        resp = await client.post(loc_signup, json=TEST_USER)
        await check_response(resp, 400, 'error')
        resp = await client.post(loc_signup, json=confirm_password(TEST_USER))
        await check_response(resp, 200, 'success')
        resp = await client.post(loc_signup, json=confirm_password(TEST_USER))
        await check_response(resp, 400, 'error')
        db_user = db_session.query(db.User).filter_by(email=TEST_USER['email']).first()
        assert db_user, 'User must be found in database'

        logger.info(f'Test sign-in - user session')
        resp = await client.post(loc_signin, json=signin_info(TEST_USER))
        result = await check_response(resp, 200, 'success')
        session_id = result.get('session_id')
        assert len(db_user.sessions) == 1, 'User must have one session'
        assert session_id == db_user.sessions[0].uuid, 'Session uuid that was given through rest must match the ' \
                                                       'database'

        logger.info(f'Test login - use session')
        resp = await client.get(loc_access)
        await check_response(resp, 401, None)
        resp = await client.get(loc_access, headers={'Authorization': session_id})
        result = await check_response(resp, 200, 'success')
        assert len(result.get('data')) == len(TEST_FILES_PART_NAME)
        resp = await client.get(loc_access)
        await check_response(resp, 401, None)

        logger.info(f'Test login - session expiration')
        # Make the session expire
        db_user_session = db_session.query(db.Session).filter_by(user_id=db_user.id).first()
        # Session should expire in 1 hours from creation
        assert db_user_session.exp_dt - db_user_session.create_dt == \
               timedelta(hours=int(os.environ['SESSION_DURATION_HOURS']))
        db_user_session.exp_dt = db_user_session.create_dt
        db_session.commit()
        resp = await client.get(loc_access, headers={'Authorization': session_id})
        await check_response(resp, 401, None)
        db_session.close()
        db_session = DataBase().create_session()
        db_user = db_session.query(db.User).filter_by(email=TEST_USER['email']).first()
        assert len(db_user.sessions) == 0, 'Session must be removed when it has expired'

        logger.info(f'Test login - session logout')
        resp = await client.post(loc_signin, json=signin_info(TEST_USER))
        result = await check_response(resp, 200, 'success')
        session_id2 = result.get('session_id')
        db_session.close()
        db_session = DataBase().create_session()
        db_user = db_session.query(db.User).filter_by(email=TEST_USER['email']).first()
        assert session_id2 != session_id, "A new session must be created after expiration"
        assert len(db_user.sessions) == 1, 'User must have one session'
        assert session_id2 == db_user.sessions[0].uuid, 'Session uuid that was given through rest must match the ' \
                                                       'database'

        resp = await client.get(loc_access, headers={'Authorization': session_id})
        await check_response(resp, 401, None)
        resp = await client.get(loc_access, headers={'Authorization': session_id2})
        await check_response(resp, 200, 'success')

        resp = await client.get(loc_logout, headers={'Authorization': session_id2})
        await check_response(resp, 200, 'success')
        db_session.close()
        db_session = DataBase().create_session()
        db_user = db_session.query(db.User).filter_by(email=TEST_USER['email']).first()
        assert len(db_user.sessions) == 0, 'Session must be removed when user logged out'
        resp = await client.get(loc_access, headers={'Authorization': session_id2})
        await check_response(resp, 401, None)
        db_session.close()
        logger.info('Test success')

    @pytest.mark.parametrize("url_base", ('/files/download', '/files/download/queued',))
    async def test_download_files(self, client, prepare_data, url_base, auth_header):
        format_location = url_base + '?filename={}&is_signed={}&user_id={}'

        start_time = time.time()

        for file_name, security, sign, content in \
                zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):
            location = format_location.format(
                file_name.replace('.' + EXTENSION_TXT, ''),
                'true' if sign else 'false',
                TEST_USER_ID)
            logger.info(f'Test GET "{location}" - Download file')
            resp = await client.get(location, headers=auth_header)
            await check_response(resp, 200, 'success')

        duration = time.time() - start_time
        if url_base == '/files/download':
            # When downloading one at a time we multiply by length
            assert duration > BaseLoader.DOWNLOAD_TIME * len(TEST_FILES_NAMES)
        else:
            # In case of queue the get should not hang!
            # We put here 1.5 seconds to make sure that there is enough time
            assert duration < 1.5

        start_time = time.time()
        # This loop executes only in the '/files/download/queued' scenario
        # Because the files will not be available after the GET request
        while len(os.listdir(DOWNLOAD_TEST_FOLDER)) != len(TEST_FILES_NAMES):
            duration = time.time() - start_time
            if duration > BaseLoader.DOWNLOAD_TIME * len(TEST_FILES_NAMES):
                assert False, "Duration for queued downloader needs to be smaller than the sequential one."
            await asyncio.sleep(1.0)

        if url_base == '/files/download/queued':
            # We expect the duration to be between the direct division and the rounding
            # We add to the max 1 second due to the processing time of the queue
            interval = {
                'min': BaseLoader.DOWNLOAD_TIME * (len(TEST_FILES_NAMES) / Handler.NUMBER_OF_QUE_LOADERS),
                'max': BaseLoader.DOWNLOAD_TIME *
                       (math.ceil(len(TEST_FILES_NAMES) / Handler.NUMBER_OF_QUE_LOADERS) + 1) + 1
            }
            assert interval['min'] < duration < interval['max'] + 1.0

        # After the files have been downloaded we compare the contents
        for file_name in os.listdir(DOWNLOAD_TEST_FOLDER):
            assert file_name in TEST_FILES_NAMES
            file_path = os.path.join(DOWNLOAD_TEST_FOLDER, file_name)
            content = TEST_FILES_CONTENTS[TEST_FILES_NAMES.index(file_name)]
            with open(file_path, 'rb') as fh:
                assert content == fh.read().decode('utf-8')

        logger.info('Test success')

    async def test_get_files(self, client, prepare_data, auth_header):
        location = '/files/list'

        logger.info(f'Test GET "{location}" - Get files')
        resp = await client.get(location, headers=auth_header)
        result = await check_response(resp, 200, 'success')

        assert len(result.get('data')) == len(TEST_FILES_PART_NAME)
        for md in result.get('data'):
            name = md.get('name')
            assert name in TEST_FILES_NAMES, f'File "{name}" not found in list.'

        logger.info('Test success')

    async def test_get_file_info(self, client, prepare_data, auth_header):
        format_location = '/files?filename={}&is_signed={}&user_id={}'

        for file_name, security, sign, content in \
                zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):

            location = format_location.format(
                file_name.replace('.' + EXTENSION_TXT, ''),
                'true' if sign else 'false',
                TEST_USER_ID)
            logger.info(f'Test GET "{location}" - Get file info')
            resp = await client.get(location, headers=auth_header)
            result = await check_response(resp, 200, 'success')
            assert result.get('data').get('content') == content
            logger.info('Test success')

    async def test_create_delete_file(self, client, prepare_data, auth_header):
        location = "/files"
        data = {
            'content': "blabla",
            'security_level': "high",
            'user_id': TEST_USER_ID,
            'is_signed': True,
        }

        logger.info(f'Test POST "{location}"')
        resp = await client.post('/files', json=data, headers=auth_header)
        result = await check_response(resp, 200, 'success')
        assert result.get('data').get('content') == data['content']
        name = result.get('data').get('name').replace('.' + EXTENSION_TXT, '')

        resp = await client.get('/files/list', headers=auth_header)
        result = await check_response(resp, 200, 'success')

        assert len(result.get('data')) == len(TEST_FILES_PART_NAME) + 1

        resp = await client.delete(f'/files/{name}', headers=auth_header)
        result = await check_response(resp, 200, 'success')

        resp = await client.get('/files/list', headers=auth_header)
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

    async def test_neg_get_file_info_missing_fields(self, client, prepare_data, auth_header):
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
                resp = await client.get(location, headers=auth_header)
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

    async def test_neg_get_file_info_incorrect_names(self, client, prepare_data, auth_header):
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
                resp = await client.get(location, headers=auth_header)
                await check_response(resp, 400, 'error')
                logger.info('Test success')
