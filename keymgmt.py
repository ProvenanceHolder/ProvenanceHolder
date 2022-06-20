import sqlite3
import nacl.encoding
import nacl.signing
import nacl.hash
from datetime import datetime

from dataclasses import dataclass

from nacl.exceptions import BadSignatureError

sha256 = nacl.hash.sha256

import pd_logger

logger = pd_logger.get_logger(__name__)

@dataclass
class Key:
    """Class for a public private key pair"""
    keyid: str  # last 16 byte of fingerprint
    name: str
    mail: str
    date: str
    fingerprint: str  # signature with privkey over (name, mail, date, pubkey)
    pubkey: str
    privkey: str


def verify(message: str, signature: str, pubkey: Key) -> bool:
    b_msg = bytes(message, 'utf-8')
    verify_key_hex = bytes(pubkey.pubkey, 'utf-8')
    verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)

    try:
        return b_msg == verify_key.verify(b_msg,
                                          nacl.encoding.HexEncoder.decode(signature))
    except BadSignatureError:
        logger.warn("Signature verification failed.")
        return False


def sign(privkey: Key, message: str) -> str:
    b_msg = bytes(message, 'utf-8')
    signing_key_hex = bytes(privkey.privkey, 'utf-8')
    signing_key = nacl.signing.SigningKey(signing_key_hex,
                                          encoder=nacl.encoding.HexEncoder)
    signed = signing_key.sign(b_msg)
    return nacl.encoding.HexEncoder.encode(signed.signature).decode('utf-8')


def create_key_from_dict(key: dict) -> Key:
    """Create a key from an incomplete key dictionary. Supposed to be a helper function."""
    if not key["date"]:
        key["date"] = datetime.now().strftime('%Y-%m-%d')

    if not key["privkey"]:
        signing_key = nacl.signing.SigningKey.generate()
        key["privkey"] = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

    if not key["pubkey"]:
        signing_key = nacl.signing.SigningKey(bytes(key["privkey"], 'utf-8'), encoder=nacl.encoding.HexEncoder)
        key["pubkey"] = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

    if not key["fingerprint"]:
        signing_key = nacl.signing.SigningKey(bytes(key["privkey"], 'utf-8'), encoder=nacl.encoding.HexEncoder)
        sign_string = key["name"] + key["mail"] + key["date"] + key["pubkey"]
        signature = nacl.encoding.HexEncoder.encode(signing_key.sign(bytes(sign_string, 'utf-8')).signature)
        key["fingerprint"] = signature.decode('utf-8')

    if not key["keyid"]:
        key["keyid"] = key["fingerprint"][-16:]

    return Key(**key)


def create_keypair(name: str, mail: str) -> Key:
    """Create a public/private key pair from name and mail."""
    key = {"keyid": "",
           "name": name,
           "mail": mail,
           "date": "",
           "fingerprint": "",
           "pubkey": "",
           "privkey": ""}
    return create_key_from_dict(key=key)


class KeyManager:
    def __init__(self, public_keys: str = 'pubkeys.db', private_keys: str = 'privkeys.db'):
        self.public_keys = public_keys
        self.private_keys = private_keys

        # Keys for querying the databases.
        self.pubkey_keys = ()
        self.privkey_keys = ()

        self.init_public_keys()
        self.init_private_keys()

    def init_public_keys(self) -> None:
        conn = sqlite3.connect(self.public_keys)

        # init data base schema
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pubkeys
                  (keyid text NOT NULL PRIMARY KEY UNIQUE,
                   name text NOT NULL,
                   mail text NOT NULL,
                   date text NOT NULL,
                   fingerprint text NOT NULL,
                   pubkey text NOT NULL UNIQUE)''')

        self.pubkey_keys = ('keyid', 'name', 'mail', 'date', 'fingerprint', 'pubkey')

        conn.commit()
        conn.close()

    def init_private_keys(self) -> None:
        conn = sqlite3.connect(self.private_keys)

        # init data base schema
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS privkeys
                  (keyid text NOT NULL PRIMARY KEY UNIQUE,
                   name text NOT NULL,
                   mail text NOT NULL,
                   date text NOT NULL,
                   fingerprint text NOT NULL,
                   pubkey text NOT NULL UNIQUE,
                   privkey text NOT NULL UNIQUE)''')

        self.privkey_keys = ('keyid', 'name', 'mail', 'date', 'fingerprint', 'pubkey', 'privkey')

        conn.commit()
        conn.close()

    def add_key_dict(self, key: dict) -> bool:
        """Add key to both, public and private key database depending on the existence of the privkey key value pair."""
        if not "privkey" in key:
            key["privkey"] = None

        return self.add_key(Key(**key))

    def add_publickey(self, key: Key) -> bool:
        database = self.public_keys
        table = 'pubkeys'
        keys = ', '.join(self.pubkey_keys)
        value_placeholders = ', '.join('?' * len(self.pubkey_keys))
        values = (key.keyid, key.name, key.mail, key.date, key.fingerprint, key.pubkey)

        sql_query = "INSERT INTO {} ({}) VALUES ({})".format(table, keys, value_placeholders)

        conn = sqlite3.connect(database)
        c = conn.cursor()
        try:
            c.execute(sql_query, values)
            return_code = True
        except sqlite3.IntegrityError as e:
            logger.error(e)
            return_code = False
        conn.commit()
        conn.close()
        return return_code

    def add_privatekey(self, key: Key) -> bool:
        database = self.private_keys
        table = 'privkeys'
        keys = ', '.join(self.privkey_keys)
        value_placeholders = ', '.join('?' * len(self.privkey_keys))
        values = (key.keyid, key.name, key.mail, key.date,
                  key.fingerprint, key.pubkey, key.privkey)

        sql_query = "INSERT INTO {} ({}) VALUES ({})".format(table, keys, value_placeholders)

        conn = sqlite3.connect(database)
        c = conn.cursor()
        try:
            c.execute(sql_query, values)
            return_code = True
        except sqlite3.IntegrityError as e:
            logger.error(e)
            return_code = False
        conn.commit()
        conn.close()
        return return_code

    def add_key(self, key: Key) -> bool:
        return_pub = self.add_publickey(key)
        return_priv = True
        if key.privkey:
            return_priv = self.add_privatekey(key)

        return return_pub and return_priv

    def get_public_key_dict(self, keyid) -> dict:
        """Get public key by keyid."""
        conn = sqlite3.connect(self.public_keys)

        c = conn.cursor()
        c.execute('SELECT * FROM pubkeys WHERE keyid=?', (keyid,))
        key_values = c.fetchone()

        # TODO throw exception if key does not exist
        if not key_values:
            logger.debug("%s not in %s.", keyid, self.public_keys)
            key = {}
        else:
            key = dict(zip(self.pubkey_keys, key_values))

        return key

    def get_public_key(self, keyid) -> Key:
        key = self.get_public_key_dict(keyid=keyid)

        if not key:
            logger.debug("%s not in %s.", keyid, self.public_keys)
            return None
        else:
            key["privkey"] = None
            return Key(**key)

    def get_private_key_dict(self, keyid) -> dict:
        """Get private key by keyid."""
        conn = sqlite3.connect(self.private_keys)

        c = conn.cursor()
        c.execute('SELECT * FROM privkeys WHERE keyid=?', (keyid,))
        key_values = c.fetchone()

        # TODO throw exception if key does not exist
        if not key_values:
            logger.debug("%s not in %s.", keyid, self.private_keys)
            key = {}
        else:
            key = dict(zip(self.privkey_keys, key_values))

        return key

    def get_private_key(self, keyid) -> Key:
        key = self.get_private_key_dict(keyid=keyid)

        if not key:
            logger.debug("%s not in %s.", keyid, self.private_keys)
            return None
        else:
            return Key(**key)

    def encrypt(self, pubkey: Key, message: str):
        pass

    def decrypt(self, privkey: Key, ciphertext: str):
        pass

    def import_key(self, filename: str):
        pass

    def export_key(self, keyid: str, filename: str):
        pass

    def delete_key(self, keyid: str):
        pass

    def search_key(self, search_string: str):
        pass
