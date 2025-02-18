import json
import os
import random
import string
import sys
from hashlib import sha256

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QInputDialog,
    QHeaderView,
)
from cryptography.fernet import Fernet

# File paths
PASSWORD_FILE = "passwords.json"
HASH_FILE = "master_password_hash.txt"
KEY_FILE = "key.bin"


# Helper Functions
def hash_password(password: str) -> str:
    """Hashes a password using SHA-256."""
    return sha256(password.encode()).hexdigest()


def save_master_password(password: str):
    """Saves the master password hash."""
    with open(HASH_FILE, "w") as file:
        file.write(hash_password(password))


def verify_master_password(password: str) -> bool:
    """Verifies the master password."""
    if not os.path.exists(HASH_FILE):
        return False
    with open(HASH_FILE, "r") as file:
        stored_hash = file.read()

    return hash_password(password) == stored_hash


def generate_password(length=12) -> str:
    """Generates a strong random password."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for _ in range(length))


def encrypt_file(key: bytes, filename: str):
    """Encrypts a file using the provided key."""
    with open(filename, "rb") as file:
        data = file.read()
    encrypted_data = Fernet(key).encrypt(data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(key: bytes, filename: str):
    """Decrypts a file using the provided key."""
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = Fernet(key).decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)


def load_passwords(key: bytes):
    """Loads passwords from the encrypted file."""
    if not os.path.exists(PASSWORD_FILE):
        return {}
    decrypt_file(key, PASSWORD_FILE)
    with open(PASSWORD_FILE, "r") as file:
        data = json.load(file)
    encrypt_file(key, PASSWORD_FILE)
    return data


def save_passwords(passwords: dict, key: bytes):
    """Saves passwords to the encrypted file."""
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file, indent=2)
    encrypt_file(key, PASSWORD_FILE)


class PasswordManager(QMainWindow):
    def __init__(self, key: bytes):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icons/app_icon.png"))
        self.key = key
        self.passwords = load_passwords(self.key)
        self.show_passwords = False  # State to track password visibility

        # Main Layout
        main_layout = QVBoxLayout()

        # Search Section
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        search_button = QPushButton("Search")
        search_button.setIcon(QIcon("icons/search.png"))
        search_button.setToolTip("Search for saved passwords.")
        search_button.clicked.connect(self.search_passwords)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_button)
        main_layout.addLayout(search_layout)

        # Add Password Section
        add_layout = QVBoxLayout()
        self.category_input = QLineEdit()
        self.service_input = QLineEdit()
        self.account_input = QLineEdit()
        self.password_input = QLineEdit()

        add_layout.addWidget(QLabel("Category:"))
        add_layout.addWidget(self.category_input)
        add_layout.addWidget(QLabel("Service:"))
        add_layout.addWidget(self.service_input)
        add_layout.addWidget(QLabel("Account:"))
        add_layout.addWidget(self.account_input)
        add_layout.addWidget(QLabel("Password:"))
        add_layout.addWidget(self.password_input)

        generate_button = QPushButton("Generate Password")
        generate_button.setIcon(QIcon("icons/generate.png"))
        generate_button.setToolTip("Generate a strong random password.")
        generate_button.clicked.connect(self.generate_password)
        add_layout.addWidget(generate_button)

        add_button = QPushButton("Add Password")
        add_button.setIcon(QIcon("icons/add.png"))
        add_button.setToolTip("Add the entered password to the list.")
        add_button.clicked.connect(self.add_password)
        add_layout.addWidget(add_button)

        main_layout.addLayout(add_layout)

        # Password Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Category", "Service", "Account", "Password", "Actions"]
        )
        self.table.setAlternatingRowColors(True)
        self.update_table(self.passwords)
        main_layout.addWidget(self.table)

        # Adjust column widths
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )  # Category
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeToContents
        )  # Service
        self.table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeToContents
        )  # Account
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.Stretch
        )  # Password
        self.table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeToContents
        )  # Actions

        # Show Passwords Toggle
        toggle_button = QPushButton("Show Passwords")
        toggle_button.setCheckable(True)
        toggle_button.setIcon(QIcon("icons/show.png"))
        toggle_button.setToolTip("Click to toggle password visibility.")
        toggle_button.toggled.connect(self.toggle_password_visibility)
        main_layout.addWidget(toggle_button)

        # Exit Button
        exit_button = QPushButton("Exit")
        exit_button.setIcon(QIcon("icons/exit.png"))
        exit_button.setToolTip("Close the application.")
        exit_button.clicked.connect(self.close)
        main_layout.addWidget(exit_button)

        # Main Widget
        main_widget = QWidget()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def toggle_password_visibility(self, checked):
        """Toggle password visibility in the table."""
        self.show_passwords = checked
        self.update_table(self.passwords)
        sender = self.sender()  # Get the button that triggered this
        sender.setText("Hide Passwords" if checked else "Show Passwords")

    def search_passwords(self):
        """Search and highlight matching passwords."""
        query = self.search_input.text().lower()
        for row in range(self.table.rowCount()):
            match_found = False
            for col in range(self.table.columnCount() - 1):  # Exclude actions column
                item = self.table.item(row, col)
                if item and query in item.text().lower():
                    match_found = True
                    break
            self.table.setRowHidden(row, not match_found)

    def update_table(self, passwords):
        """Update the table to display passwords (masked or visible)."""
        self.table.setRowCount(0)
        for category, services in passwords.items():
            for service, details in services.items():
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(category))
                self.table.setItem(row, 1, QTableWidgetItem(service))
                self.table.setItem(row, 2, QTableWidgetItem(details["account"]))

                # Show password or mask it
                password = details["password"] if self.show_passwords else "*****"
                self.table.setItem(row, 3, QTableWidgetItem(password))

                # Add copy button
                copy_button = QPushButton("Copy")
                copy_button.setToolTip("Copy the password to clipboard.")
                copy_button.clicked.connect(
                    lambda _, pw=details["password"]: self.copy_to_clipboard(pw)
                )
                self.table.setCellWidget(row, 4, copy_button)

    def copy_to_clipboard(self, text):
        """Copy text to the clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")

    def generate_password(self):
        password = generate_password()
        self.password_input.setText(password)

    def add_password(self):
        category = self.category_input.text()
        service = self.service_input.text()
        account = self.account_input.text()
        password = self.password_input.text()

        if not category or not service or not account or not password:
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return

        if category not in self.passwords:
            self.passwords[category] = {}
        self.passwords[category][service] = {"account": account, "password": password}

        save_passwords(self.passwords, self.key)
        self.update_table(self.passwords)

        QMessageBox.information(self, "Success", "Password added successfully!")
        self.category_input.clear()
        self.service_input.clear()
        self.account_input.clear()
        self.password_input.clear()


def main():
    app = QApplication(sys.argv)

    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    else:
        with open(KEY_FILE, "rb") as file:
            key = file.read()

    if not os.path.exists(HASH_FILE):
        password, ok = QInputDialog.getText(
            None,
            "Set Master Password",
            "Enter a new master password:",
            QLineEdit.Password,
        )
        if ok and password.strip():
            save_master_password(password.strip())
            QMessageBox.information(None, "Success", "Master password has been set.")
        else:
            QMessageBox.warning(
                None, "Input Error", "Master password cannot be empty. Exiting."
            )
            sys.exit(1)

    verified = False
    while not verified:
        password, ok = QInputDialog.getText(
            None,
            "Enter Master Password",
            "Enter your master password to unlock the application:",
            QLineEdit.Password,
        )
        if ok and password.strip():
            if verify_master_password(password.strip()):
                verified = True
            else:
                QMessageBox.warning(
                    None, "Authentication Failed", "Incorrect password. Try again."
                )
        else:
            QMessageBox.warning(
                None, "Input Error", "Master password is required. Exiting."
            )
            sys.exit(1)

    window = PasswordManager(key)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
