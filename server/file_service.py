# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import typing
import server.utils as utils
from server.crypto import BaseCipher, AESCipher, RSACipher, HashAPI


class FileService(metaclass=utils.SingletonMeta):
    """Singleton class with methods for working with file system.

    """
    EXTENSION = 'txt'

    def __init__(self, *args, **kwargs):
        path = kwargs.get('path')
        self.path = path  # Calls setter

    @property
    def path(self) -> str:
        """Working directory path getter.

        Returns:
            Str with working directory path.

        """

        return self.__path

    @path.setter
    def path(self, value: str):
        """Working directory path setter.

        Args:
            value (str): Working directory path.

        """

        if not value:
            raise ValueError('Path must have a valid value!')
        if not os.path.exists(value):
            os.mkdir(value)
        self.__path = value

    def get_file_data(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file.

        Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, filename format is invalid,
            ValueError: if security level is invalid, if user_id not specified.

        """

        basename = f'{filename}.{self.EXTENSION}'
        full_filename = os.path.join(self.path, basename)
        assert os.path.exists(full_filename), f'File "{basename}" does not exist'

        filename_parts = filename.split('_')
        assert len(filename_parts) == 2, 'Invalid format of file name'
        security_level = filename_parts[1]

        if security_level == 'low':
            cipher = BaseCipher()
        else:
            raise ValueError('Security level is invalid')

        metadata = utils.get_metadata(full_filename)
        with open(full_filename, 'rb') as file_handler:
            metadata['content'] = cipher.decrypt(file_handler, filename).decode('utf-8')
        return metadata

    async def get_file_data_async(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file. Asynchronous version.

        Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, filename format is invalid,
            ValueError: if security level is invalid.

        """

        pass

    def get_files(self) -> typing.List[typing.Dict[str, str]]:
        """Get info about all files in working directory.

        Returns:
            List of dicts, which contains info about each file. Keys:
                name (str): name of file with .txt extension.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (str): size of file in bytes.

        """

        data = []
        files = [f for f in os.listdir(self.path) if os.path.isfile(os.path.join(self.path, f))]
        files = list([f for f in files if len(f.split('.')) > 1 and f.split('.')[-1] == self.EXTENSION])

        for file_name in files:
            file_path = os.path.join(self.path, file_name)
            data.append(utils.get_metadata(file_path))

        return data

    def create_file(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

        Returns:
            Dict, which contains name of created file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if user_id is not set,
            ValueError: if security level is invalid, if user_id not specified.

        """

        # Retry until a new file can be created
        while 1:
            basename = f'{utils.generate_string()}_{security_level}.{self.EXTENSION}'
            file_path = os.path.join(self.path, basename)
            # When it doesn't exist we can create it
            if not os.path.exists(file_path):
                break

        if security_level == 'low':
            cipher = BaseCipher()
        else:
            raise ValueError('Security level is invalid')

        with open(file_path, 'wb') as file_handler:
            if not content:
                # Content needs to be empty string for md5 correct calculation
                content = ''

            data = bytes(content, 'utf-8')
            cipher.write_cipher_text(data, file_handler, basename.split('.')[0])

        metadata = utils.get_metadata(file_path)
        metadata.pop('edit_date')
        metadata['content'] = content
        return metadata

    async def create_file_async(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

        Returns:
            Dict, which contains name of created file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if user_id is not set,
            ValueError: if security level is invalid, if user_id not specified.

        """

        pass

    def delete_file(self, filename: str):
        """Delete file.

        Args:
            filename (str): Filename without .txt file extension.

        Returns:
            Str with filename with .txt file extension.

        Raises:
            AssertionError: if file does not exist.

        """

        basename = f'{filename}.{self.EXTENSION}'
        file_path = os.path.join(self.path, basename)
        assert os.path.exists(file_path), f'File "{basename}" does not exist'

        os.remove(file_path)

        return basename


class FileServiceSigned(FileService, metaclass=utils.SingletonMeta):
    """Singleton class with methods for working with file system and file signatures.

    """

    def get_file_data(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file.

        Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, filename format is invalid, signatures are not match,
            signature file does not exist,
            ValueError: if security level is invalid.

        """

        pass

    async def get_file_data_async(self, filename: str, user_id: int = None) -> typing.Dict[str, str]:
        """Get full info about file. Asynchronous version.

        Args:
            filename (str): Filename without .txt file extension,
            user_id (int): User Id.

        Returns:
            Dict, which contains full info about file. Keys:
                name (str): name of file with .txt extension.
                content (str): file content.
                create_date (str): date of file creation.
                edit_date (str): date of last file modification.
                size (int): size of file in bytes,
                user_id (int): user Id.

        Raises:
            AssertionError: if file does not exist, filename format is invalid, signatures are not match,
            signature file does not exist,
            ValueError: if security level is invalid.

        """

        pass

    def create_file(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file with signature file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

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

    async def create_file_async(
            self, content: str = None, security_level: str = None, user_id: int = None) -> typing.Dict[str, str]:
        """Create new .txt file with signature file.

        Method generates name of file from random string with digits and latin letters.

        Args:
            content (str): String with file content,
            security_level (str): String with security level,
            user_id (int): User Id.

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
