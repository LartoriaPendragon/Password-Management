import secrets
import hashlib
from getpass import getpass
from sqlalchemy import create_engine, Column, Integer, Text, text
from sqlalchemy.orm import sessionmaker, declarative_base
from rich import print as printc
from rich.console import Console
from utils.dbconfig import create_app, db
import string

console = Console()
Base = declarative_base()


class Secrets(Base):
    """Class for Secrets table"""

    # Define table name and columns
    __tablename__ = 'secrets'
    entry_id = Column(Integer, primary_key=True)
    masterkey_hash = Column(Text, nullable=False)
    device_secret = Column(Text, nullable=False)


def checkConfig():
    """
    Checks if the 'pm' database exists.
    :return: True if the database exists, False otherwise.
    """
    # Use the app context to get the engine
    with create_app(database_uri='mysql+pymysql://admin:root123@localhost').app_context():
        # SQL query to check if the database exists
        query = text("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'pm'")
        try:
            with db.engine.connect() as connection:
                # Execute the query and fetch the results
                results = connection.execute(query).fetchall()
                if len(results) != 0:
                    # If the result set is not empty, the database exists
                    return True
        except Exception as e:
            # If an exception occurs, the database does not exist
            printc("[yellow][-] Exception: [/yellow]", e)
            printc("[yellow][-] The 'pm' database does not exist. Proceeding to create it.[/yellow]")
            return False


def generateDeviceSecret(length=10):
    """
    Generates a cryptographically secure device secret of specified length.
    Uses the secrets module to generate a random string of uppercase letters and digits.

    Args:
    - length (int): Length of the device secret to generate. Default is 10.

    Returns:
    - device_secret (str): Generated device secret.
    """
    alphabet = string.ascii_uppercase + string.digits
    device_secret = ''.join(secrets.choice(alphabet) for i in range(length))
    return device_secret


def create_tables(engine):
    """
    Creates database tables based on models defined in SQLAlchemy.

    Args:
    - engine: SQLAlchemy engine to use for creating tables.

    Returns:
    - None
    """
    Base.metadata.create_all(engine)


def make():
    # Create Flask app and check if database already exists
    # app = create_app(database_uri='mysql+pymysql://admin:root123@localhost/pm')
    db_exists = checkConfig()

    if not db_exists:
        printc("[green][+] Creating new config [/green]")

        # Create database if it doesn't exist
        engine = create_engine('mysql+pymysql://admin:root123@localhost', echo=True)
        query_create_db = text("CREATE DATABASE IF NOT EXISTS pm;")
        query_use_db = text("USE pm;")
        query_create_tables = text("CREATE TABLE IF NOT EXISTS secrets (entry_id INT NOT NULL AUTO_INCREMENT, "
                                   "masterkey_hash TEXT NOT NULL, device_secret TEXT NOT NULL, PRIMARY KEY (entry_id));")
        try:
            with engine.connect() as connection:
                connection.execute(query_create_db)
                printc("[green][+][/green] Database 'pm' created")
                connection.execute(query_use_db)
                connection.execute(query_create_tables)
                printc("[green][+][/green] Created necessary tables")
        except Exception as e:
            printc("[red][!] Exception: [/red]", e)
            printc("[red][!] An error occurred while trying to create db. Check if the database with the name 'pm' "
                   "already exists - if it does, delete it and try again.")
            return

    else:
        printc("[red][!] Already Configured! [/red]")
        return

    # Get the user's master password
    mp = ""
    printc(
        "[green][+] A [bold]MASTER PASSWORD[/bold] is the only password you will need to remember in-order to access "
        "all your other passwords. Choosing a strong [bold]MASTER PASSWORD[/bold] is essential because all your other "
        "passwords will be [bold]encrypted[/bold] with a key that is derentry_ided from your [bold]MASTER PASSWORD["
        "/bold]."
        "Therefore, please choose a strong one that has upper and lower case characters, numbers and also special "
        "characters. Remember your [bold]MASTER PASSWORD[/bold] because it won't be stored anywhere by this program, "
        "and you also cannot change it once chosen. [/green]\n")

    # Prompt user to enter and confirm their master password
    while 1:
        mp = getpass("Choose a MASTER PASSWORD: ")
        if mp == getpass("Re-type: ") and mp != "":
            break
        printc("[yellow][-] Please try again.[/yellow]")

    # Hash the master password
    hashed_mp = hashlib.sha256(mp.encode()).hexdigest()
    printc("[green][+][/green] Generated hash of MASTER PASSWORD")

    # Generate a device secret
    ds = generateDeviceSecret()
    printc("[green][+][/green] Device Secret generated")

    # Add master password hash and device secret to the database
    Session = sessionmaker(bind=engine)
    session = Session()
    secret = Secrets(masterkey_hash=hashed_mp, device_secret=ds)
    session.add(secret)
    session.commit()
    session.close()

    # Updates user on successful completion
    printc("[green][+] Configuration completed successfully![/green]")


if __name__ == '__main__':
    make()