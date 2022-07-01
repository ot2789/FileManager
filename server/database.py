# Copyright 2019 by Kirill Kanin.
# All rights reserved.

import os
import psycopg2
from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.orm.session import Session as DBSession
from sqlalchemy.engine.base import Engine
from datetime import datetime, timedelta
from uuid import uuid4
from server.crypto import HashAPI
from server.utils import SingletonMeta


class DataBase(metaclass=SingletonMeta):
    """Singleton class for ORM.

    """

    __is_inited = False
    __instance = None
    __db_string = "postgresql://{}:{}@{}/{}".format(
        os.environ['DB_USER'],
        os.environ['DB_PASSWORD'],
        os.environ['DB_HOST'],
        os.environ['DB_NAME'])
    Base = declarative_base()

    def __init__(self):
        if not self.__is_inited:
            self.__engine = create_engine(self.__db_string, pool_size=10, max_overflow=20)
            self.Base.metadata.create_all(bind=self.__engine)
            self.__is_inited = True

    class BaseModel:
        """Base database model.

        """

        @declared_attr
        def __tablename__(self):
            return self.__name__

        id = Column(Integer, name='Id', primary_key=True, autoincrement=True)
        create_dt = Column(DateTime, name='Create Date')

        def __init__(self):
            self.create_dt = datetime.now()

    class User(BaseModel, Base):
        """User model.

        """

        email = Column(String, name='Email', unique=True)
        password = Column(String, name='Password')
        name = Column(String, name='Name')
        surname = Column(String, name="Surname")
        last_login_dt = Column(DateTime, name="Last Login Date")
        sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')

        def __init__(self, email: str, password: str, name: str, surname: str = None, sessions: list = None, role=None):
            super().__init__()
            self.email = email
            self.password = password
            self.name = name
            self.surname = surname

            if sessions:
                self.sessions.extend(sessions)

    class Role(BaseModel, Base):
        """Role model.

        """

        def __init__(self, name: str, users: list = None, methods: list = None):
            pass

    class Method(BaseModel, Base):
        """Method model.

        """

        def __init__(self, name: str, shared: bool = False, roles: list = None):
            pass

    class Session(BaseModel, Base):
        """Session model.

        """

        uuid = Column(String, name='UUID', unique=True)
        exp_dt = Column(DateTime, name='Expiration Date')
        user_id = Column(Integer, ForeignKey('User.Id', ondelete='CASCADE', onupdate='CASCADE'))
        user = relationship('User', back_populates='sessions')

        def __init__(self, user):
            super().__init__()
            self.uuid = str(uuid4())
            self.exp_dt = self.create_dt + timedelta(hours=int(os.environ['SESSION_DURATION_HOURS']))
            self.user = user
            self.user.last_login_dt = self.create_dt

    class MethodRole(Base):
        """Many to many model for method and role models.

        """
        # We create a dummy id here so that the sqlalchemy can create the table
        # We will remove this later.
        dummy_id = Column(Integer, name='Id', primary_key=True, autoincrement=True)

        __tablename__ = 'MethodRole'

        def __init__(self, method=None, role=None):
            pass

    @property
    def engine(self) -> Engine:
        """Database engine getter.

        Returns:
            Database engine.

        """

        return self.__engine

    def create_session(self) -> DBSession:
        """Create and get database connection session.

        Returns:
            Database connection session.

        """

        return sessionmaker(bind=self.__engine)()

    def init_system(self):
        """Initialize database.

        """

        self.Base.metadata.drop_all(bind=self.__engine)
        self.Base.metadata.create_all(bind=self.__engine)
