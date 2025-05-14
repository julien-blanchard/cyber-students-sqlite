from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler

from .base import BaseTest

import urllib.parse

from api.conf import STREAM_KEY, PEPPER, SALT_TEST
from api.handlers.encryption_decryption import *
from api.handlers.database_operations import *

PATH_CURR = os.getcwd()
PATH_TO_NONCES_DB = os.path.join(PATH_CURR,"databases","db_nonces.db")
PATH_TO_SALTS_DB = os.path.join(PATH_CURR,"databases","db_salts.db")

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    @coroutine
    def register(self):
        salt_as_hex = SALT_TEST
        pepper_as_hex = PEPPER

        # Encryption, based on the functions stored in encryption_decryption.py
        encrypted_password = hashToScrypt(self.password,salt_as_hex,pepper_as_hex)
        updateTable(PATH_TO_SALTS_DB,"SALTS",self.email,salt_as_hex)
        yield self.get_app().db.users.insert_one({
            'email': self.email,
            'password': encrypted_password.hex(),
            'displayName': self.display_name,
            "fullAddress": "testFullAddress",
            "dateOfBirth": "testDateOfBirth",
            "disabilities": "testDisabilities",
            "phoneNumber": "testPhoneNumber"
        })

    @coroutine
    def login(self):
        yield self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token': self.token, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)