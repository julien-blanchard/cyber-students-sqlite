# Base modules
import os
from json import dumps
from logging import info

# Tornado
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler

# Third-party packages
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import sqlite3

# Local imports
from .encryption_decryption import *
from .database_operations import *

# Stream cipher key from the config file, as per the instructions doc
from api.conf import STREAM_KEY, PEPPER

# Path to the SQLite databases, will work on any os
PATH_CURR = os.getcwd()
PATH_TO_NONCES_DB = os.path.join(PATH_CURR,"databases","db_nonces.db")
PATH_TO_SALTS_DB = os.path.join(PATH_CURR,"databases","db_salts.db")

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            # adding in new fields
            full_address = body["fullAddress"]
            if not isinstance(full_address, str):
                raise Exception()
            date_of_birth = body["dateOfBirth"]
            if not isinstance(date_of_birth, str):
                raise Exception()
            # for disabilities, users might not feel comfortable sharing so the default value is N/A
            disabilities = body["disabilities"]
            if disabilities is None:
                disabilities = "N/A"
            # phone numbers will be parsed as strings as some users might use different formats
            phone_number = body["phoneNumber"]
            if not isinstance(phone_number,str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, a password, your full address, your date of birth, and display name!')
            return

        # new error messages added
        if not email:
            self.send_error(400, message='The email address is invalid!')
            return
        if not password:
            self.send_error(400, message='The password is invalid!')
            return
        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return
        if not full_address:
            self.send_error(400, message='The address is invalid!')
            return
        if not date_of_birth:
            self.send_error(400, message='The date of birth is invalid!')
            return
        # skipping disabilities on purpose, same reason as above
        if not phone_number:
            self.send_error(400, message='The phone number is invalid!')
            return
        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
        
        # preparing the salts / nonces for each user. Using .hex() as they'll be stored as strings within the db
        salt = os.urandom(16)
        salt_as_hex = salt.hex()
        nonce = os.urandom(16)
        nonce_as_hex = nonce.hex()
        pepper_as_hex = PEPPER

        # Encryption, based on the functions stored in encryption_decryption.py
        encrypted_password = hashToScrypt(password,salt_as_hex,PEPPER)

        # encrypting each field using a unique key-nonce pair per user
        encrypted_full_address = encryptToChaCha(STREAM_KEY,nonce_as_hex,full_address)
        encrypted_display_name = encryptToChaCha(STREAM_KEY,nonce_as_hex,display_name)
        encrypted_date_of_birth = encryptToChaCha(STREAM_KEY,nonce_as_hex,date_of_birth)
        encrypted_disabilities = encryptToChaCha(STREAM_KEY,nonce_as_hex,disabilities)
        encrypted_phone_number = encryptToChaCha(STREAM_KEY,nonce_as_hex,phone_number)
        
        # we save the email-nonce and email-salt pairs into a database
        updateTable(PATH_TO_NONCES_DB,"NONCES",email,nonce_as_hex)
        updateTable(PATH_TO_SALTS_DB,"SALTS",email,salt_as_hex)

        # inserting all the encrypted fields into mongodb, as strings
        yield self.db.users.insert_one({
            'email': email,
            'password': encrypted_password.hex(),
            'displayName': encrypted_display_name.hex(),
            "fullAddress": encrypted_full_address.hex(),
            "dateOfBirth": encrypted_date_of_birth.hex(),
            "disabilities": encrypted_disabilities.hex(),
            "phoneNumber": encrypted_phone_number.hex(),
        })

        self.set_status(200)

        # showing the fields in plaintext to the user
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response["fullAddress"] = full_address
        self.response["dateOfBirth"] = date_of_birth
        self.response["disabilities"] = disabilities
        self.response["phoneNumber"] = phone_number

        self.write_json()
