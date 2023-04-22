import utils.aesutil
import pyperclip

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from rich import print as printc
from rich.console import Console
from rich.table import Table
from utils.add import Entry


# Computes master key
def computeMasterKey(mp, ds):
    # Convert master password and device secret to bytes
    password = mp.encode()
    salt = ds.encode()

    # Derive the key from the master password and device secret using PBKDF2 key derivation function
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    return key


# Retrieves entries that match search criteria
def retrieveEntries(mp, ds, search, decryptPassword=True):
    # Build query based on search criteria
    query = Entry.query
    for i in search:
        query = query.filter(getattr(Entry, i) == search[i])
    results = query.all()

    if len(results) == 0:
        printc("[yellow][-][/yellow] No results for the search")
        return

    password_to_copy = None
    # Create table to display results
    table = Table(title="Results")
    table.add_column("Site Name")
    table.add_column("URL")
    table.add_column("Email")
    table.add_column("Username")
    table.add_column("Password")

    for i in results:
        row = [i.sitename, i.siteurl, i.email, i.username]
        if decryptPassword:
            if len(results) > 1:
                printc(
                    "[yellow][-][/yellow] More than one result found for the search, therefore not extracting the "
                    "password. Be more specific.")
            else:
                password = results[0].password
                # Decrypt the password using AES encryption
                decrypted_password = utils.aesutil.decrypt(bytes.fromhex(password), mp, ds)
                row.append("{hidden}")
                password_to_copy = decrypted_password
        else:
            row.append("{hidden}")
        table.add_row(*row)

    console = Console()
    console.print(table)

    # Copy the password to clipboard if there is only one result
    if password_to_copy is not None:
        pyperclip.copy(password_to_copy)
        printc("[+] Password copied to clipboard")
