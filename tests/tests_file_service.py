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
# from server.crypto import HashAPI, AESCipher, RSACipher
import server.file_service_no_class as FileServiceNoClass

# Logging will present extra information when running pytest
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

EXTENSION_TXT = 'txt'
TEST_FOLDER = os.path.abspath('../storage')
TEST_FILES_NAMES = ['beefDead.txt', '12345678.txt', 'testFile.txt', 'catMouse.txt']
TEST_FILES_CONTENTS = ['lmao', 'test1', 'test2', 'ABC']
TEST_FILE_NO_EXIST = "notExist.txt"


def create_and_move_to_test_folder():
    if not os.path.exists(TEST_FOLDER):
        os.mkdir(TEST_FOLDER)
    os.chdir(TEST_FOLDER)


def create_test_files():
    for file_name, content in zip(TEST_FILES_NAMES, TEST_FILES_CONTENTS):
        full_path = os.path.join(os.getcwd(), file_name)
        with open(full_path, 'wb') as file_handler:
            data = bytes(content, 'utf-8')
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
    create_and_move_to_test_folder()
    create_test_files()
    yield
    cleanup()


class TestSuite:
    def test_get_files(self, prepare_data):
        def extract_name(metadata):
            return metadata.get('name')

        def is_test_file(metadata):
            return metadata.get('name') in TEST_FILES_NAMES

        logger.info('Test get files')
        data = FileServiceNoClass.get_files()
        exists_files = list(map(extract_name, filter(is_test_file, data)))
        assert len(exists_files) == len(TEST_FILES_NAMES)
        for file in TEST_FILES_NAMES:
            assert file in exists_files

        assert not (TEST_FILE_NO_EXIST in exists_files)
        logger.info('Test success')

    def test_get_file_info(self, prepare_data):
        test_file = TEST_FILES_NAMES[1].split('.')[0]
        logger.info('Test get file info - existing')

        data = FileServiceNoClass.get_file_data(test_file)
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))
        assert filename == TEST_FILES_NAMES[1]

        content = data.get('content')
        assert content == TEST_FILES_CONTENTS[1]

        logger.info('Test success')

    def test_get_file_info_not_exists(self, prepare_data):
        logger.info('Test get file info - not existing')
        test_file = TEST_FILE_NO_EXIST.split('.')[0]

        try:
            data = FileServiceNoClass.get_file_data(test_file)
        except AssertionError as e:
            pass
        else:
            assert False, "File should not exist"

        logger.info('Test success')

    def test_create_file(self, prepare_data):
        logger.info('Test create file - with content')
        content = 'Something there'

        data = FileServiceNoClass.create_file(content)
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))
        assert data.get('content') == content

        logger.info('Test success')
        logger.info('Test create file - without content')

        data = FileServiceNoClass.create_file()
        filename = data.get('name')
        assert os.path.exists(os.path.join(os.getcwd(), filename))
        assert not data.get('content')

        logger.info('Test success')
        logger.info('Test get files - with the created files')

        data = FileServiceNoClass.get_files()
        assert len(data) == len(TEST_FILES_NAMES) + 2

        logger.info('Test success')

    def test_delete_file(self, prepare_data):
        test_file_part = TEST_FILES_NAMES[2].split('.')[0]

        logger.info('Test delete file - existing')
        FileServiceNoClass.delete_file(test_file_part)
        assert not os.path.exists(os.path.join(os.getcwd(), TEST_FILES_NAMES[2]))

        data = FileServiceNoClass.get_files()
        assert len(data) == len(TEST_FILES_NAMES) - 1

        logger.info('Test success')

    def test_delete_file_not_exists(self, prepare_data):
        test_file_part = TEST_FILE_NO_EXIST.split('.')[0]

        logger.info('Test delete file - not existing')
        try:
            FileServiceNoClass.delete_file(test_file_part)
        except AssertionError as e:
            pass
        else:
            assert False, "Function should throw an error."
        assert not os.path.exists(os.path.join(os.getcwd(), TEST_FILE_NO_EXIST))

        logger.info('Test success')

    def test_change_dir(self, prepare_data):
        new_test_folder = 'test_folders'

        logger.info('Test change dir')

        data = FileServiceNoClass.get_files()
        assert len(data) == len(TEST_FILES_NAMES)

        os.mkdir(new_test_folder)
        FileServiceNoClass.change_dir(new_test_folder)

        data = FileServiceNoClass.get_files()
        assert len(data) == 0

        logger.info('Test success')

