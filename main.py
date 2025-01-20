import sys
import os
import random
import string
import json
import threading
from hashlib import sha256
from cryptography.fernet import Fernet

class AutoLock:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.timer = None

    def start_timer(self):
        self.stop_timer()
        self.timer = threading.Timer(self.timeout, self.lock)
        self.timer.start()

    def stop_timer(self):
        if self.timer:
            self.timer.cancel()

    def lock(self):
        print("\nSession timed out. Locking application.")
        exit()

def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()

def save_master_password_hash(password: str, hash_file: str):
    hashed_password = hash_password(password)
    with open(hash_file, 'w') as file:
        file.write(hashed_password)

def verify_master_password(entered_password: str, hash_file: str) -> bool:
    with open(hash_file, 'r') as file:
        stored_hash = file.read()
    return hash_password(entered_password) == stored_hash

def generate_password(length=12) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def is_strong_password(password: str) -> bool:
    if len(password) < 8 or \
            not any(char.isupper() for char in password) or \
            not any(char.islower() for char in password) or \
            not any(char.isdigit() for char in password) or \
            not any(char in string.punctuation for char in password):
        return False
    return True

def encrypt_file(key: bytes, filename: str):
    with open(filename, 'rb') as file:
        data = file.read()
    encrypted_data = Fernet(key).encrypt(data)
    with open(filename, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(key: bytes, filename: str):
    with open(filename, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = Fernet(key).decrypt(encrypted_data)
    with open(filename, 'wb') as file:
        file.write(decrypted_data)

def safe_load_passwords(filename: str) -> dict:
    if not os.path.exists(filename):
        print(f"{filename} not found. Starting with an empty password list.")
        return {}
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        print(f"Error reading {filename}. File might be corrupted.")
        return {}

def add_password_by_category(passwords: dict, category: str, service: str, account: str, password: str):
    if category not in passwords:
        passwords[category] = {}
    passwords[category][service] = {"account": account, "password": password}

def search_passwords(query: str, passwords: dict):
    results = {}
    for category, services in passwords.items():
        for service, details in services.items():
            if query.lower() in service.lower():
                results[service] = details
    return results

def main():
    PASSWORD_FILE = "passwords.json"
    HASH_FILE = "master_password_hash.txt"
    SALT_FILE = "salt.bin"

    if not os.path.exists(HASH_FILE):
        master_password = input("Set up your master password: ")
        save_master_password_hash(master_password, HASH_FILE)
        print("Master password saved securely.")

    master_password = input("Enter your master password: ")
    if not verify_master_password(master_password, HASH_FILE):
        print("Invalid password. Exiting.")
        exit()

    salt = os.urandom(16) if not os.path.exists(SALT_FILE) else open(SALT_FILE, 'rb').read()
    key = Fernet.generate_key()
    passwords = safe_load_passwords(PASSWORD_FILE)
    lock = AutoLock()

    while True:
        lock.start_timer()
        print("\nPassword Manager Menu")
        print("1. Add a Password")
        print("2. View Passwords")
        print("3. Search Passwords")
        print("4. Exit")

        choice = input("Choose an option: ")
        if choice == "1":
            print("\nAdding a New Password")
            print("Please provide the following details:")

            # Ask for category
            category = input("Category (e.g., Social Media, Email, Banking): ").strip()
            if not category:
                print("Category cannot be empty. Please try again.")
                continue

            # Ask for service
            service = input("Service Name (e.g., Gmail, Facebook): ").strip()
            if not service:
                print("Service Name cannot be empty. Please try again.")
                continue

            # Ask for account
            account = input("Account (e.g., your email or username for this service): ").strip()
            if not account:
                print("Account cannot be empty. Please try again.")
                continue

            # Ask for password
            password = input("Password (leave blank to auto-generate a strong password): ").strip()
            if not password:
                password = generate_password()
                print(f"Generated Password: {password} (Make sure to save it securely!)")

            # Add the password to the system
            add_password_by_category(passwords, category, service, account, password)
            print(f"Password for {service} under {category} category has been saved.")
        elif choice == "2":
            print(json.dumps(passwords, indent=2))
        elif choice == "3":
            query = input("Search query: ")
            print(search_passwords(query, passwords))
        elif choice == "4":
            # Stop the auto-lock timer if running
            lock.stop_timer()

            # Save and encrypt the password file
            print("Saving and encrypting your password file before exiting...")
            with open(PASSWORD_FILE, 'w') as file:
                json.dump(passwords, file)
            encrypt_file(key, PASSWORD_FILE)

            # Exit the program
            print("Goodbye! Your session has ended.")
            sys.exit()  # Cleanly terminates the program

if __name__ == "__main__":
    main()
