from json import dumps
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.logout import LogoutHandler

from .base import BaseTest

import urllib.parse

from api.conf import STREAM_KEY, PEPPER, SALT_TEST
from api.handlers.encryption_decryption import *
from api.handlers.database_operations import *

PATH_CURR = os.getcwd()
PATH_TO_NONCES_DB = os.path.join(PATH_CURR,"databases","db_nonces.db")
PATH_TO_SALTS_DB = os.path.join(PATH_CURR,"databases","db_salts.db")

class LogoutHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/logout', LogoutHandler)])
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
            'displayName': 'testDisplayName',
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
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_logout(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

    def test_logout_without_token(self):
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})
        body = {}

        response = self.fetch('/logout', method='POST', body=dumps(body))
        self.assertEqual(400, response.code)

    def test_logout_twice(self):
        headers = HTTPHeaders({'X-Token': self.token})
        body = {}

        response = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/logout', headers=headers, method='POST', body=dumps(body))
        self.assertEqual(403, response_2.code)
