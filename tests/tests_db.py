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
    def test_init_database(self, db_session):
        user = db_session.query(DataBase.User).first()
        assert user is not None
        assert user.email == os.environ['ADMIN_EMAIL']

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

    def test_user_method_roles(self, db: DataBase, db_session, user: DataBase.User):
        methods = [db.Method('meth1'), db.Method('meth2'), db.Method('meth3')]
        for m in methods:
            db_session.add(m)
        roles = [
            db.Role('role2', [user], [methods[1], methods[2]]),
            db.Role('role1', [user], [methods[0], methods[1]])
        ]
        # We reverse this to assign the user to role1
        db_session.add_all(roles)
        db_session.commit()
        roles.reverse()

        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
        assert user.role.name == 'role1'
        role = db_session.query(DataBase.Role).filter_by(name='role1').first()
        role_methods = [m.method.name for m in role.methods]
        assert methods[0].name in role_methods
        assert methods[1].name in role_methods
        assert methods[2].name not in role_methods

        def check_roles(method_name, expected_roles):
            api_methods = [mr.role.name for mr in \
                           db_session.query(DataBase.Method).filter_by(name=method_name).first().roles]
            if expected_roles:
                for r in expected_roles:
                    assert r in api_methods
            else:
                assert len(api_methods) == 0

        check_roles('meth1', ('role1',))
        check_roles('meth2', ('role1', 'role2',))
        check_roles('meth3', ('role2',))

        # Changing user role
        user.role = db_session.query(DataBase.Role).filter_by(name='role2').first()
        db_session.commit()
        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()

        # Checking if it has been correctly updated.
        assert user.role.name == 'role2'
        role = db_session.query(DataBase.Role).filter_by(name='role2').first()
        role_methods = [m.method.name for m in role.methods]
        assert methods[0].name not in role_methods
        assert methods[1].name in role_methods
        assert methods[2].name in role_methods

        # Deleting role1 should not delete user
        db_session.query(DataBase.Role).filter_by(name='role1').delete()
        db_session.commit()
        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
        assert user.email == TEST_USER['email']

        check_roles('meth1', tuple())
        check_roles('meth2', ('role2',))
        check_roles('meth3', ('role2',))

        # Here we just want to decouple meth2 from role2
        method_roles = db_session.query(DataBase.MethodRole).filter_by(method=methods[1], role=roles[1])
        assert len(method_roles.all()) == 1
        method_roles.delete()
        db_session.commit()

        check_roles('meth1', tuple())
        check_roles('meth2', tuple())
        check_roles('meth3', ('role2',))

        # Deleting role2 should delete user
        db_session.query(DataBase.Role).filter_by(name='role2').delete()
        db_session.commit()
        user = db_session.query(DataBase.User).filter_by(email=TEST_USER['email']).first()
        assert user is None

        check_roles('meth1', tuple())
        check_roles('meth2', tuple())
        check_roles('meth3', tuple())

        existing_roles = [u.name for u in db_session.query(DataBase.User).all()]
        for r in ('role1', 'role2',):
            assert r not in existing_roles

        existing_methods = [m.name for m in db_session.query(DataBase.Method).all()]
        for m in ('meth1', 'meth3',):
            assert m in existing_methods
            db_session.query(DataBase.Method).filter_by(name=m).delete()

