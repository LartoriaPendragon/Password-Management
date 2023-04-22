import argparse
from getpass import getpass
import hashlib
import pyperclip
import os
from rich import print as printc

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from utils.dbconfig import create_app
from config import Secrets
from utils import add
import utils.retrieve
import utils.generate
import utils.dbconfig

# Create Flask app
app = create_app()

parser = argparse.ArgumentParser(description='Description')

# Define command line arguments
parser.add_argument('option', help='(a)dd / (e)xtract / (g)enerate')
parser.add_argument("-s", "--name", help="Site name")
parser.add_argument("-u", "--url", help="Site URL")
parser.add_argument("-e", "--email", help="Email")
parser.add_argument("-l", "--login", help="Username")
parser.add_argument("--length", help="Length of the password to generate", type=int)
parser.add_argument("-c", "--copy", action='store_true', help='Copy password to clipboard')

# Parse the arguments
args = parser.parse_args()


def check_and_initialize_secrets():
    # Create SQLAlchemy engine and session
    engine = create_engine('mysql+pymysql://admin:root123@localhost/pm')
    Session = sessionmaker(bind=engine)
    session = Session()

    # Check if any secrets exist in the database
    secret = session.query(Secrets).first()

    if secret is None:
        # If no secrets exist, prompt user to initialize them
        printc("[green][+][/green] No secrets found in the database. Initializing secrets...")
        master_password = getpass("Enter a master password: ")
        device_secret = input("Enter a device secret: ")
        initialize_secrets(master_password, device_secret)
    else:
        # If secrets exist, simply print a message
        printc("[green][+][/green] Secrets found in the database.")


def initialize_secrets(master_password, device_secret):
    hashed_master_password = hashlib.sha256(master_password.encode()).hexdigest()

    engine = create_engine('mysql+pymysql://admin:root123@localhost/pm')
    Session = sessionmaker(bind=engine)
    session = Session()

    secret = Secrets(masterkey_hash=hashed_master_password, device_secret=device_secret)
    session.add(secret)
    session.commit()

    printc("[green][+][/green] Secrets initialized in the database")


def inputAndValentry_idateMasterPassword():
    mp = getpass("MASTER PASSWORD: ")
    hashed_mp = hashlib.sha256(mp.encode()).hexdigest()

    engine = create_engine('mysql+pymysql://admin:root123@localhost/pm')
    Session = sessionmaker(bind=engine)
    session = Session()

    secret = session.query(Secrets).first()

    if secret is None:
        printc("[red][!] The secrets were not initialized. Please run the script again.[/red]")
        return None

    if hashed_mp != secret.masterkey_hash:
        printc("[red][!] WRONG! [/red]")
        return None

    return [mp, secret.device_secret]


def create_secrets_if_needed():
    engine = create_engine('mysql+pymysql://admin:root123@localhost/pm')
    Session = sessionmaker(bind=engine)
    session = Session()

    secret = session.query(Secrets).first()

    if secret is None:
        mp = getpass("Enter a new master password: ")
        hashed_mp = hashlib.sha256(mp.encode()).hexdigest()
        device_secret = os.urandom(32).hex()

        new_secrets = Secrets(masterkey_hash=hashed_mp, device_secret=device_secret)
        session.add(new_secrets)
        session.commit()

        printc("[green][+][/green] Secrets have been initialized.")


# Main function
def main():
    create_secrets_if_needed()

    # Add new entry
    if args.option in ["add", "a"]:
        if args.name == None or args.url == None or args.login == None:
            if args.name == None:
                printc("[red][!][/red] Site Name (-s) required ")
            if args.url == None:
                printc("[red][!][/red] Site URL (-u) required ")
            if args.login == None:
                printc("[red][!][/red] Site Login (-l) required ")
            return

        if args.email == None:
            args.email = ""

        res = inputAndValentry_idateMasterPassword()
        if res is not None:
            with app.app_context():
                password = getpass("Password: ")
                hex_password = password.encode('utf-8').hex()
                utils.add.add_entry(res[0], res[1], args.name, args.url, args.email, args.login, hex_password)

    # Extract entry
    if args.option in ["extract", "e"]:
        with app.app_context():
            res = inputAndValentry_idateMasterPassword()

            search = {}
            if args.name is not None:
                search["sitename"] = args.name
            if args.url is not None:
                search["siteurl"] = args.url
            if args.email is not None:
                search["email"] = args.email
            if args.login is not None:
                search["username"] = args.login

            if res is not None:
                utils.retrieve.retrieveEntries(res[0], res[1], search, decryptPassword=args.copy)

    # Generate password
    if args.option in ["generate", "g"]:
        if args.length == None:
            printc("[red][+][/red] Specify length of the password to generate (--length)")
            return
        password = utils.generate.generatePassword(args.length)
        pyperclip.copy(password)
        printc("[green][+][/green] Password generated and copied to clipboard")


if __name__ == '__main__':
    main()
