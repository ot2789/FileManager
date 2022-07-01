# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import server.config
import pytest
import logging
from server.database import DataBase

# Logging will present extra information when running pytest
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


TEST_USER = {
    'email': 'test@fileman.com',
    'password': '1234qwer',
    'name': 'Test',
    'surname': 'Master',
}

@pytest.fixture(scope="class")
def erase_db():
    db = DataBase()
    db.init_system()
    return db

@pytest.fixture
def db():
    return DataBase()

@pytest.fixture
def db_session():
    session = DataBase().create_session()
    yield session
    session.close()

@pytest.fixture
def user(db, db_session):
    user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
    if not user:
        db_session.add(db.User(**TEST_USER))
        db_session.commit()
        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
    return user


@pytest.mark.usefixtures("erase_db")
class TestSuite:
    def test_empty_database(self, db_session):
        assert db_session.query(DataBase.User).first() is None

    def test_insert_user(self, db: DataBase, db_session):
        db_session.add(db.User(**TEST_USER))
        db_session.commit()
        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
        for k in TEST_USER:
            assert TEST_USER[k] == getattr(user, k)
        assert not user.sessions

    def test_login_session_user(self, db: DataBase, db_session, user: DataBase.User):
        db_session.add(db.Session(user))
        db_session.commit()
        assert len(user.sessions) == 1
        db_session.query(db.Session).filter_by(user_id=user.id).delete()
        db_session.commit()
        assert len(user.sessions) == 0
        db_session.add(db.Session(user))
        db_session.commit()
        assert len(user.sessions) == 1
        # When we remove a user, sessions need to be deleted as well
        db_session.query(db.User).filter_by(id=user.id).delete()
        db_session.commit()
        sessions = db_session.query(db.Session).all()
        assert len(sessions) == 0

