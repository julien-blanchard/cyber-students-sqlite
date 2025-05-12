# base modules
import os
from datetime import datetime, timedelta
from time import mktime

# tornado stuff
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

# db and cryptography imports
import sqlite3
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# local imports
from .encryption_decryption import *
from .database_operations import *

# Path to the SQLite database, will work on any os
PATH_CURR = os.getcwd()
PATH_TO_SALTS_DB = os.path.join(PATH_CURR,"databases","db_salts.db")

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1,
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Now that we now the email, we retrieve its corresponding salt from the SQLite database
        salt_as_hex = retrieveFromTable(PATH_TO_SALTS_DB,"SALTS",email)

        # it took me a while to figure this out: matching plaintexts return None, non matching ones raise an error (changed to 0 in my function)
        hash_match = dehashFromScrypt(password,user["password"],salt_as_hex)

        # slight change to what was there before, but same logic really
        if hash_match is not None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
