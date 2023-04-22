import random
import string


def generatePassword(length):
    """
    Generate a random password string of specified length.

    Parameters:
    length (int): The length of the password to generate.

    Returns:
    str: The generated password string.
    """
    return ''.join([random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length)])
