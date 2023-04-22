# Password-Management

Password-Management is a command-line password manager that helps you store, retrieve, and generate secure passwords. It securely encrypts your passwords using AES encryption and a master password that only you know.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Features

- Store encrypted passwords
- Retrieve and decrypt passwords
- Generate strong random passwords
- Copy passwords to clipboard
- Search for stored passwords

## Requirements

- Python 3.6 or higher
- PyMySQL
- SQLAlchemy
- Crypto
- Rich
- Pyperclip

## Installation

1. Clone the repository:
```bash
git clone https://github.com/LartoriaPendragon/Password-Management.git
```

2. Change to the project directory:
```bash
cd Password-Management
```

3. Create a virtual environment:
```bash
python3 -m venv venv
```

4. Activate the virtual environment:
   - For Linux/Mac:
```bash
source venv/bin/activate
```
   - For Windows:
```bash
venv\Scripts\activate
```

5. Install required packages:
```bash
pip install -r requirements.txt
```


## Usage

### Add an entry
```bash
python pm.py add -s <site_name> -u <site_url> -l <login> -e <email> (optional)
```

### Extract an entry
```bash
python pm.py extract -s <site_name> -u <site_url> -l <login> -e <email> (optional) -c (optional, to copy password to clipboard)
```

### Generate a password
```bash
python pm.py generate --length <password_length> -c (optional, to copy password to clipboard)
```

## License

This project is licensed under the MIT License.
