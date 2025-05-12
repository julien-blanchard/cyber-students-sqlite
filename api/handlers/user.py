from tornado.web import authenticated
from .auth import AuthHandler

# Local imports
from .encryption_decryption import *
from .database_operations import *
from api.conf import STREAM_KEY

# Path to the SQLite database, will work on any os
PATH_CURR = os.getcwd()
PATH_TO_NONCES_DB = os.path.join(PATH_CURR,"databases","db_nonces.db")

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)

        # we have the user's email, so we can retrieve its corresponding nonces from the SQLite db
        nonce_as_hex = retrieveFromTable(PATH_TO_NONCES_DB,"NONCES",self.current_user["email"])

        # decrypting each field, one by one
        decrypted_display_name = decryptFromChaCha(
            STREAM_KEY,
            nonce_as_hex,
            self.current_user["display_name"]
        )
        decrypted_full_address = decryptFromChaCha(
            STREAM_KEY,
            nonce_as_hex,
            self.current_user["fullAddress"]
        )
        decrypted_date_of_birth = decryptFromChaCha(
            STREAM_KEY,
            nonce_as_hex,
            self.current_user["dateOfBirth"]
        )
        decrypted_disabilities = decryptFromChaCha(
            STREAM_KEY,
            nonce_as_hex,
            self.current_user["disabilities"]
        )
        decrypted_phone_number = decryptFromChaCha(
            STREAM_KEY,
            nonce_as_hex,
            self.current_user["phoneNumber"]
        )

        # and finally just picking which fields will be shown to the user in the terminal
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = str(decrypted_display_name, "utf-8")
        self.response["fullAddress"] = str(decrypted_full_address, "utf-8")
        self.response["dateOfBirth"] = str(decrypted_date_of_birth, "utf-8")
        self.response["disabilities"] = str(decrypted_disabilities, "utf-8")
        self.response["phoneNumber"] = str(decrypted_phone_number, "utf-8")
        self.write_json()
