from modules import encryptor
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
salt_size = 16
key_size = 32
iterations = 100000
chunk_size = 64 * 1024

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath, password):
    salt = os.urandom(salt_size)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    outfile = filepath + ".enc"
    with open(filepath, 'rb') as f_in, open(outfile, 'wb') as f_out:
        f_out.write(salt + iv)
        while chunk := f_in.read(chunk_size):
            if len(chunk) % 16 != 0:
                padding = 16 - len(chunk) % 16
                chunk += bytes([padding]) * padding
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())
    print(f"[+] File encrypted to {outfile}")

def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f_in:
        salt = f_in.read(salt_size)
        iv = f_in.read(16)
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        out_path = filepath.replace(".enc", ".dec")
        with open(out_path, 'wb') as f_out:
            while chunk := f_in.read(chunk_size):
                decrypted_chunk = decryptor.update(chunk)
                f_out.write(decrypted_chunk)
            f_out.write(decryptor.finalize())

        # remove padding
        with open(out_path, 'rb+') as f_out:
            f_out.seek(-1, os.SEEK_END)
            padding_len = f_out.read(1)[0]
            f_out.truncate(f_out.tell() - padding_len)

    print(f"[+] File decrypted to {out_path}")




def banner():
    print(r"""
  ____             _                  _____           _ 
 |  _ \ ___   __ _(_)_ __ ___   ___  | ____|_ __   __| |
 | |_) / _ \ / _` | | '_ ` _ \ / _ \ |  _| | '_ \ / _` |
 |  __/ (_) | (_| | | | | | | |  __/ | |___| | | | (_| |
 |_|   \___/ \__, |_|_| |_| |_|\___| |_____|_| |_|\__,_|
             |___/                                     
    """)

def main():
    banner()
    print("1. Encrypt File")
    print("2. Decrypt File")
    choice = input("Enter choice: ")

    if choice == "1":
        file = input("Enter file to encrypt: ")
        if not os.path.exists(file):
            print("File not found.")
            return
        password = input("Enter password: ")
        encryptor.encrypt_file(file, password)

    elif choice == "2":
        file = input("Enter file to decrypt (.enc): ")
        if not file.endswith(".enc"):
            print("File must end with .enc")
            return
        password = input("Enter password: ")
        encryptor.decrypt_file(file, password)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
