import json
import os
import random
import string
import sys
from hashlib import sha256

from PySide6.QtCore import QTimer
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
)
from cryptography.fernet import Fernet


# File paths
PASSWORD_FILE = "passwords.json"
HASH_FILE = "master_password_hash.txt"
KEY_FILE = "key.bin"


# Helper Functions
def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()


def save_master_password(password: str):
    with open(HASH_FILE, "w") as file:
        file.write(hash_password(password))


def verify_master_password(password: str) -> bool:
    if not os.path.exists(HASH_FILE):
        return False
    with open(HASH_FILE, "r") as file:
        stored_hash = file.read()
    return hash_password(password) == stored_hash


def generate_password(length=12) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for _ in range(length))


def encrypt_file(key: bytes, filename: str):
    with open(filename, "rb") as file:
        data = file.read()
    encrypted_data = Fernet(key).encrypt(data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(key: bytes, filename: str):
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = Fernet(key).decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)


def load_passwords(key: bytes):
    if not os.path.exists(PASSWORD_FILE):
        return {}
    decrypt_file(key, PASSWORD_FILE)
    with open(PASSWORD_FILE, "r") as file:
        data = json.load(file)
    encrypt_file(key, PASSWORD_FILE)
    return data


def save_passwords(passwords: dict, key: bytes):
    with open(PASSWORD_FILE, "w") as file:
        json.dump(passwords, file, indent=2)
    encrypt_file(key, PASSWORD_FILE)


# GUI Classes
class PasswordManager(QMainWindow):
    def __init__(self, key: bytes):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowIcon(QIcon("icons/app_icon.png"))
        self.key = key
        self.passwords = load_passwords(self.key)

        # Auto-lock timer
        self.lock_timer = QTimer()
        self.lock_timer.setInterval(300000)  # 5 minutes
        self.lock_timer.timeout.connect(self.lock_application)
        self.lock_timer.start()

        # Main Layout
        main_layout = QVBoxLayout()

        # Search Section
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setToolTip("Enter a search term (e.g., 'Email', 'Facebook').")
        search_button = QPushButton("Search")
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
        generate_button.clicked.connect(self.generate_password)
        generate_button.setToolTip("Click to generate a strong random password.")
        add_layout.addWidget(generate_button)

        add_button = QPushButton("Add Password")
        add_button.setIcon(QIcon("icons/add.png"))
        add_button.clicked.connect(self.add_password)
        add_button.setToolTip("Click to save the entered password.")
        add_layout.addWidget(add_button)

        # Center-align buttons
        button_layout = QHBoxLayout()
        button_layout.addWidget(generate_button)
        button_layout.addWidget(add_button)
        add_layout.addLayout(button_layout)

        main_layout.addLayout(add_layout)

        # Password Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            ["Category", "Service", "Account", "Password"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet(
            "QTableWidget { alternate-background-color: #2c2c2c; }"
        )
        self.update_table(self.passwords)
        main_layout.addWidget(self.table)

        # Exit Button
        exit_button = QPushButton("Exit")
        exit_button.setToolTip("Click to exit the application.")
        exit_button.clicked.connect(self.close)
        main_layout.addWidget(exit_button)

        # Main Widget
        main_widget = QWidget()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

    def lock_application(self):
        QMessageBox.warning(
            self, "Session Timeout", "Session timed out. Please log in again."
        )

        self.close()

    def search_passwords(self):
        query = self.search_input.text().lower()
        filtered = {}
        for category, services in self.passwords.items():
            for service, details in services.items():
                if query in category.lower() or query in service.lower():
                    if category not in filtered:
                        filtered[category] = {}
                    filtered[category][service] = details
        self.update_table(filtered)

    def update_table(self, passwords):
        self.table.setRowCount(0)
        for category, services in passwords.items():
            for service, details in services.items():
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(category))
                self.table.setItem(row, 1, QTableWidgetItem(service))
                self.table.setItem(row, 2, QTableWidgetItem(details["account"]))
                self.table.setItem(row, 3, QTableWidgetItem(details["password"]))

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


# Main Function
def main():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    else:
        with open(KEY_FILE, "rb") as file:
            key = file.read()

    app = QApplication(sys.argv)

    # Apply Material Dark Style
    with open("assets/themes/MaterialDark.qss", "r") as style_file:
        app.setStyleSheet(style_file.read())

    if not os.path.exists(HASH_FILE):
        master_password, ok = QLineEdit.getText(
            None, "Set Master Password", "Enter a new master password:"
        )
        if ok:
            save_master_password(master_password)

    window = PasswordManager(key)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
