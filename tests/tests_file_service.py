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
    pass


def create_test_files():
    pass


def cleanup():
    pass


@pytest.fixture(scope='function')
def prepare_data(request):
    pass




class TestSuite:
    pass

