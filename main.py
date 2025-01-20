import os
import random
import string
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode


# Create key from master password
def create_key(master_password: str, salt: bytes):
 kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
 )
 return urlsafe_b64encode(kdf.derive(master_password.encode()))

# Generate a strong random password
def generate_password(length= 12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Encrypt data using a key
def encrypt_data(key, data):
    fernet = Fernet(key)
    return fernet.encrypt(data.encode())

# Decrypt data using a key
def decrypt_data(key, encrypted_data):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

# Save password to a file
def save_passwords(filename, passwords):
    with open(filename, 'w') as file:
        json.dump(passwords, file)

# Load passwords from a file
def load_passwords(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, 'r') as file:
        return json.load(file)

# Main program
def password_manager():
    #constants
    PASSWORD_FILE = 'passwords.json'
    SALT_FILE = 'salt.bin'

    # load or create a salt
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as file:
            salt = file.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as file:
            file.write(salt)

    # prompt for master password
    master_password = input('Enter your master password: ')
    key = create_key(master_password, salt)

    # load passwords
    passwords = load_passwords(PASSWORD_FILE)

    while True:
        print("\nPassword Manager Menu")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Generate a strong password")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            service = input("Enter the service name (e.g. email, website): ")
            account = input("Enter the account name (e.g. username, email): ")
            password = input("Enter the password (or leave blank to generate a strong password): ")


            if not password:
                password = generate_password()
                print(f"Generated a strong password: {password}")

            encrypted_password = encrypt_data(key, password)
            passwords[service] = { 'account': account, 'password': encrypted_password.decode() }
            save_passwords(PASSWORD_FILE, passwords)
            print(f"Password for {service} has been saved successfully")

        elif choice == '2':
            # Retrieve a password
            service = input("Enter the service name: ")
            if service in passwords:
                encrypted_password = passwords[service]['password']
                decrypted_password = decrypt_data(key, encrypted_password.encode())
                print(f"Service: {service}")
                print(f"Account: {passwords[service]['account']}")
                print(f"Password: {decrypted_password}")
            else:
                print(f"No password found for service {service}")

        elif choice == '3':
            length = int(input("Enter the desired password length: " ))
            print(f"Generated password: {generate_password(length)}")

        elif choice == '4':
            # Exit the program
            print("Exiting the Password Manager. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == '__main__':
    password_manager()










