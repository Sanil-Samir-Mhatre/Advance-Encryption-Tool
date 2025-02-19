import os
import base64
from tkinter import Tk, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend


# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,  # AES-256 requires a 256-bit (32-byte) key
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


# Helper function to clean up and normalize file paths
def clean_path(path: str) -> str:
    return path.strip().strip('"').strip("'")


# Function for file selection using the GUI
def select_file(prompt="Select a file"):
    root = Tk()
    root.withdraw()  # Hide the root window
    root.wm_attributes("-topmost", 1)  # Bring file dialog to the front
    file_path = filedialog.askopenfilename(title=prompt)
    if not file_path:
        raise ValueError("No file selected!")
    return file_path


# Function for saving file with GUI
def save_file(prompt="Save file as"):
    root = Tk()
    root.withdraw()  # Hide the root window
    root.wm_attributes("-topmost", 1)  # Bring file dialog to the front
    file_path = filedialog.asksaveasfilename(title=prompt)
    if not file_path:
        raise ValueError("No save location selected!")
    return file_path



# Encrypt a file
def encrypt_file():
    try:
        password = input("Enter a password for encryption: ")
        print("Select the file you want to encrypt.")
        input_file = select_file()  # File selection via GUI
        print("Select where to save the encrypted file.")
        output_file = save_file()  # Save file dialog via GUI

        salt = os.urandom(16)  # Generate a random salt
        key = derive_key(password, salt)
        iv = os.urandom(16)  # Generate a random initialization vector (IV)

        # Read file content to encrypt
        with open(input_file, "rb") as f:
            plaintext = f.read()

        # Encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Write the encrypted data to the output file
        with open(output_file, "wb") as f:
            f.write(base64.b64encode(salt + iv + ciphertext))  # Store salt + IV + ciphertext

        print(f"Encryption successful! Encrypted file saved as: {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Decrypt a file
def decrypt_file():
    try:
        password = input("Enter the password for decryption: ")
        print("Select the encrypted file for decryption.")
        input_file = select_file()  # File selection via GUI
        print("Select where to save the decrypted file.")
        output_file = save_file()  # Save file dialog via GUI

        # Read the encrypted content
        with open(input_file, "rb") as f:
            data = base64.b64decode(f.read())

        salt, iv, ciphertext = data[:16], data[16:32], data[32:]  # Extract components

        key = derive_key(password, salt)

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Write the decrypted content to the output file
        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"Decryption successful! Decrypted file saved as: {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Main function
def main():
    print("Welcome to the AES-256 File Encryption Tool!")
    print("Choose an option:")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Enter your choice (1 or 2): ")

    if choice == "1":
        encrypt_file()
    elif choice == "2":
        decrypt_file()
    else:
        print("Invalid choice. Exiting.")


if __name__ == "__main__":
    main()
