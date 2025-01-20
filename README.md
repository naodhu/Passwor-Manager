# Password Manager

## Overview

The Password Manager is a secure and user-friendly tool for managing your passwords. It allows users to store, retrieve,
and generate strong passwords securely, all protected by a master password. The program features AES encryption,
password strength validation, and an auto-lock timer for enhanced security.

---

## Features

1. **Master Password Authentication**:
    - Protects access to the password manager with a hashed master password.
2. **Password Storage**:
    - Organizes passwords by categories (e.g., Social Media, Email).
3. **Encryption**:
    - Encrypts passwords and storage files with AES encryption.
4. **Password Generation**:
    - Automatically generates strong, random passwords.
5. **Password Strength Validation**:
    - Ensures user-provided passwords meet security standards.
6. **Auto-Lock Timer**:
    - Automatically logs out after inactivity.
7. **Search Functionality**:
    - Quickly find passwords by keyword or service name.
8. **Error Handling**:
    - Manages missing files or corrupted data gracefully.

---

## Setup Instructions

### Prerequisites

- Python 3.8 or later installed on your machine.
- Install required libraries:
  ```bash
  pip install cryptography

# Running the Application

### Clone this repository:

```bash
git clone <repository_url>
cd Password-Manager
```

# Run the Program

### Run the program:

```bash
python main.py
```

# Usage Examples

### Adding a Password

- When prompted, provide the **category**, **service name**, **account**, and a password.
- Leave the password field blank to auto-generate a strong password.

### Retrieving a Password

- Search for saved passwords by entering the **service name** or a **keyword**.

### Secure Storage

- Passwords are stored in an encrypted file, ensuring they cannot be read without the master password.

---

# Future Enhancements

1. **Graphical User Interface** using `tkinter`, `PyQt`, or `Kivy`.
2. **Cloud Backup Integration** with AWS or Google Drive.
3. **Multi-User Support** for shared use cases.

---

# License

This project is licensed under the MIT License. Feel free to use, modify, and distribute it as needed.

---

# Acknowledgments

This project was developed as a learning exercise to enhance Python skills in encryption, file handling, and secure
application development.

