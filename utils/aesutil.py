from Crypto.Cipher import AES
import hashlib
import os


def encrypt(password, master_password, device_secret):
    """
    Encrypts the given password using AES encryption with a key derived from the master password and device secret.

    Args:
        password (str): The password to be encrypted.
        master_password (str): The master password used to derive the encryption key.
        device_secret (str): The device secret used to derive the encryption key.

    Returns:
        tuple: A tuple containing the encrypted password in hexadecimal format and a randomly generated entry ID.

    """
    # Derive the encryption key from the master password and device secret
    key = hashlib.sha256((master_password + device_secret).encode('utf-8')).digest()

    # Generate a random initialization vector
    iv = os.urandom(AES.block_size)

    # Encrypt the password using AES with the derived key and initialization vector
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_password = iv + cipher.encrypt(password.encode('utf-8'))

    # Generate a random entry ID and return the encrypted password and entry ID
    entry_id = int.from_bytes(os.urandom(2), 'big', signed=False)
    hex_password = encrypted_password.hex()
    return hex_password, entry_id


def decrypt(encrypted_password, master_password, device_secret):
    """
    Decrypts the given encrypted password using AES encryption with a key derived from the master password and device secret.

    Args:
        encrypted_password (bytes): The encrypted password in hexadecimal format.
        master_password (str): The master password used to derive the encryption key.
        device_secret (str): The device secret used to derive the encryption key.

    Returns:
        str: The decrypted password.

    """
    # Derive the encryption key from the master password and device secret
    key = hashlib.sha256((master_password + device_secret).encode('utf-8')).digest()

    # Extract the initialization vector from the encrypted password
    iv = encrypted_password[:AES.block_size]

    # Decrypt the password using AES with the derived key and initialization vector
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_password = cipher.decrypt(encrypted_password[AES.block_size:]).decode('utf-8')

    # Return the decrypted password
    return decrypted_password
