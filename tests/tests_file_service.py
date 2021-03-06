# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import shutil
import sys

import pytest
import json
import logging
import server.utils as utils
import server.config
# from aiohttp import web
# from server.handler import Handler
# from server.database import DataBase
from server.crypto import HashAPI, AESCipher, RSACipher
from server.file_service import FileService, FileServiceSigned

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


class TestSuite:
    @pytest.mark.parametrize('file_service', [FileService, FileServiceSigned])
    def test_get_files(self, file_service, prepare_data):
        file_service = file_service()  # We want the instance

        def extract_name(metadata):
            return metadata.get('name')

        def is_test_file(metadata):
            return metadata.get('name') in TEST_FILES_NAMES

        logger.info('Test get files')
        data = file_service.get_files()
        exists_files = list(map(extract_name, filter(is_test_file, data)))
        assert len(exists_files) == len(TEST_FILES_NAMES)
        for file in TEST_FILES_NAMES:
            assert file in exists_files

        assert not (TEST_FILE_NO_EXIST in exists_files)
        logger.info('Test success')

    @pytest.mark.parametrize('file_service, file_index', [(FileService, 1), (FileServiceSigned, 2)])
    def test_get_file_info(self, file_service, file_index, prepare_data):
        file_service = file_service()  # We want the instance
        test_file = TEST_FILES_NAMES[file_index].split('.')[0]
        logger.info('Test get file info - existing')

        data = file_service.get_file_data(test_file, TEST_USER_ID)
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))
        assert filename == TEST_FILES_NAMES[file_index]

        content = data.get('content')
        assert content == TEST_FILES_CONTENTS[file_index]

        logger.info('Test success')

    @pytest.mark.parametrize('file_service', [FileService, FileServiceSigned])
    def test_get_file_info_not_exists(self, file_service, prepare_data):
        file_service = file_service()  # We want the instance
        logger.info('Test get file info - not existing')
        test_file = TEST_FILE_NO_EXIST.split('.')[0]

        try:
            data = file_service.get_file_data(test_file, TEST_USER_ID)
        except AssertionError as e:
            pass
        else:
            assert False, "File should not exist"

        logger.info('Test success')

    @pytest.mark.parametrize('file_service, security_level', [
        (FileService, 'low'), (FileServiceSigned, 'low'), (FileService, 'medium'), (FileServiceSigned, 'high')
        ])
    def test_create_file(self, file_service, security_level, prepare_data):
        file_service = file_service()  # We want the instance

        logger.info(f'Test create file - with content')
        content = 'Something there'

        data = file_service.create_file(content, security_level=security_level, user_id=TEST_USER_ID)
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))

        data = file_service.get_file_data(filename.split('.')[0], TEST_USER_ID)
        assert data.get('content') == content

        logger.info('Test success')
        logger.info(f'Test create file - without content')

        data = file_service.create_file(security_level=security_level, user_id=TEST_USER_ID)
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))

        data = file_service.get_file_data(filename.split('.')[0], TEST_USER_ID)
        assert data.get('content') == ''

        logger.info('Test success')
        logger.info(f'Test get files - with the created files')

        data = file_service.get_files()
        assert len(data) == len(TEST_FILES_NAMES) + 2

        logger.info('Test success')

    @pytest.mark.parametrize('file_service, file_index, signature_delta, key_delta',
                             [(FileService, 0, 0, 0), (FileService, 1, 0, -1), (FileServiceSigned, 3, -1, -1)]
                             )
    def test_delete_file(self, file_service, file_index, signature_delta, key_delta, prepare_data):
        file_service = file_service()  # We want the instance
        test_file_part = TEST_FILES_NAMES[file_index].split('.')[0]

        logger.info('Test delete file - existing')
        file_service.delete_file(test_file_part)
        assert not os.path.exists(os.path.join(os.getcwd(), TEST_FILES_NAMES[file_index]))

        data = file_service.get_files()
        assert len(data) == len(TEST_FILES_NAMES) - 1

        assert len(get_files_by_extension(os.getcwd(), 'md5')) == \
               len(list(filter(lambda x: x, TEST_FILES_SIGNED))) + signature_delta

        assert len(get_files_by_extension(os.getcwd(), 'bin')) == \
               len(list(filter(lambda x: x != 'low', TEST_FILES_SECURITY))) + key_delta

        logger.info('Test success')

    @pytest.mark.parametrize('file_service', [FileService, FileServiceSigned])
    def test_delete_file_not_exists(self, file_service, prepare_data):
        file_service = file_service()  # We want the instance
        test_file_part = TEST_FILE_NO_EXIST.split('.')[0]

        logger.info('Test delete file - not existing')
        try:
            file_service.delete_file(test_file_part)
        except AssertionError as e:
            pass
        else:
            assert False, "Function should throw an error."
        assert not os.path.exists(os.path.join(os.getcwd(), TEST_FILE_NO_EXIST))

        logger.info('Test success')

    @pytest.mark.parametrize('file_service', [FileService, FileServiceSigned])
    def test_change_dir(self, file_service, prepare_data):
        file_service = file_service()  # We want the instance
        new_test_folder = 'test_folders'

        logger.info('Test change dir')

        data = file_service.get_files()
        assert len(data) == len(TEST_FILES_NAMES)

        os.mkdir(new_test_folder)
        file_service.path = new_test_folder

        data = file_service.get_files()
        assert len(data) == 0

        logger.info('Test success')

    def test_tamper_file(self, prepare_data):
        def alter_content(file, restore=False):
            with open(file, 'rb') as file_handle:
                data = file_handle.read()
            data = bytearray(data)  # Make it readable
            if not restore:
                data[0] += 1
            else:
                data[0] -= 1
            with open(file, 'wb') as file_handle:
                file_handle.write(data)

        for file_name, security, sign, content in \
                zip(TEST_FILES_NAMES, TEST_FILES_SECURITY, TEST_FILES_SIGNED, TEST_FILES_CONTENTS):
            file_service = FileService()
            logger.info(f'Test file tampering security "{security}" {"w/" if sign else "w/o"} signature')
            if sign:
                file_service = FileServiceSigned()
            file_name_no_ext = file_name.replace(f'.{EXTENSION_TXT}', '')
            # Only case when it will not detect tampering
            if security == 'low' and not sign:
                alter_content(file_name)
                new_content = file_service.get_file_data(file_name_no_ext, TEST_USER_ID).get('content')
                assert new_content != content, \
                    "Content should be different in the only case which doesn't handle tampering"
                alter_content(file_name, restore=True)
                restored_content = file_service.get_file_data(file_name_no_ext, TEST_USER_ID).get('content')
                assert restored_content == content, \
                    "Something happened with file, restoration of the content failed."
            # Here tampering should be detected via signature or via decryption failure
            else:
                tamper_file_list = []
                # First test the tampering of signature
                if sign:
                    tamper_file_list.append(file_name.replace('.'+EXTENSION_TXT, '.md5'))
                # After this test the the tampering of file
                tamper_file_list.append(file_name)
                for tamper_file in tamper_file_list:
                    alter_content(tamper_file)
                    try:
                        new_content = file_service.get_file_data(file_name_no_ext, TEST_USER_ID).get('content')
                    # ValueError for MAC check failure, AssertionError for signature mismatch
                    except (ValueError, AssertionError,) as e:
                        pass
                    else:
                        assert False, "Tampering should be detected"
                    # The ctime may change for different platforms (such as linux).
                    # Therefore we skip the check for file restoring.
                    if tamper_file == file_name:
                        continue
                    alter_content(tamper_file, restore=True)
                    restored_content = file_service.get_file_data(file_name_no_ext, TEST_USER_ID).get('content')
                    assert restored_content == content, \
                        "Something happened with file, restoration of the content failed."
        logger.info('Test success')



