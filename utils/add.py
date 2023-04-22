from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from utils import aesutil
from utils.dbconfig import db


# Define Entry class to represent a database entry
class Entry(db.Model):
    __table_args__ = {'extend_existing': True}
    entry_id = db.Column(db.BigInteger, primary_key=True)
    sitename = db.Column(db.Text, nullable=False)
    siteurl = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    username = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)


# Function to add a new entry to the database
def add_entry(master_password, device_secret, sitename, siteurl, email, username, hex_password):
    # Encrypt the password using AES encryption
    encrypted_password, entry_id = aesutil.encrypt(hex_password, master_password, device_secret)

    # Create a new entry object and add it to the database
    entry = Entry(sitename=sitename, siteurl=siteurl, email=email, username=username, password=encrypted_password,
                  entry_id=entry_id)
    db.session.add(entry)
    db.session.commit()
    print("New entry added to the database.")


# Function to compute the master key using PBKDF2 key derivation function
def computeMasterKey(mp, ds):
    password = mp.encode()
    salt = ds.encode()
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return key


# Function to check if an entry already exists in the database
def checkEntry(session, sitename, siteurl, email, username):
    entry = session.query(Entry).filter_by(sitename=sitename, siteurl=siteurl, email=email, username=username).first()
    return entry is not None
