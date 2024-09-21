#!/usr/bin/env python3
#
# To run first install cryptography & colorama:
# pip install cryptography colorama
#
#

import os
import base64
import getpass
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from colorama import init, Fore, Style

# init colorama
init(autoreset=True)


def derive_key(password: str, salt: bytes, iterations: int = 4_206_660) -> bytes:
    """
    derive a 256-bit AES key from given password and salt using PBKDF2 HMAC SHA256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode())
    return key


def encrypt_private_key(private_key: str, password: str) -> str:
    """
    encrypt the private key using AES-256 GCM
    returns a base64-encoded string containing salt, nonce, ciphertext, and tag
    format: base64(salt):base64(nonce):base64(ciphertext):base64(tag)
    """
    # generate random salt
    salt = os.urandom(16)  # 128-bit salt

    # derive key
    key = derive_key(password, salt)

    # init AESGCM with derived key
    aesgcm = AESGCM(key)

    # generate random nonce
    nonce = os.urandom(12)  # 96-bit nonce for GCM

    # encrypt private key
    ciphertext = aesgcm.encrypt(nonce, private_key.encode(), None)

    # in AESGCM the tag is appended to the ciphertext
    tag = ciphertext[-16:]
    actual_ciphertext = ciphertext[:-16]

    # encode each component using base64 (web friendly)
    b64_salt = base64.urlsafe_b64encode(salt).decode()
    b64_nonce = base64.urlsafe_b64encode(nonce).decode()
    b64_ciphertext = base64.urlsafe_b64encode(actual_ciphertext).decode()
    b64_tag = base64.urlsafe_b64encode(tag).decode()

    # combine all parts into a single string separated by colons
    encrypted_str = f"{b64_salt}:{b64_nonce}:{b64_ciphertext}:{b64_tag}"
    return encrypted_str


def decrypt_private_key(encrypted_str: str, password: str) -> str:
    """
    decrypt encrypted private key string using AES-256 GCM
    expects encrypted string in the format: salt:nonce:ciphertext:tag
    returns decrypted private key as a string
    """
    try:
        # split encrypted string into its components
        b64_salt, b64_nonce, b64_ciphertext, b64_tag = encrypted_str.split(':')

        # decode each component from base64
        salt = base64.urlsafe_b64decode(b64_salt)
        nonce = base64.urlsafe_b64decode(b64_nonce)
        ciphertext = base64.urlsafe_b64decode(b64_ciphertext)
        tag = base64.urlsafe_b64decode(b64_tag)

        # derive key
        key = derive_key(password, salt)

        # init AESGCM with derived key
        aesgcm = AESGCM(key)

        # combine ciphertext and tag for decryption
        combined_ciphertext = ciphertext + tag

        # decrypt the data
        decrypted_private_key = aesgcm.decrypt(nonce, combined_ciphertext, None).decode()
        return decrypted_private_key

    except InvalidTag:
        print(
            Fore.RED + "\nDecryption failed: Invalid password or corrupted data. Please ensure the encrypted string and password are correct.")
        sys.exit(1)
    except (ValueError, KeyError, base64.binascii.Error) as e:
        print(
            Fore.RED + "\nDecryption failed: Malformed encrypted string. Please ensure the encrypted string is correctly formatted.")
        sys.exit(1)


def get_private_key_input() -> str:
    """
    prompt user to input their private key
    accept only a single line of input and hides the input as it's entered
    """
    private_key = getpass.getpass("Enter your private key (input hidden): " + Style.RESET_ALL)
    if not private_key:
        print(Fore.RED + "Private key cannot be empty." + Style.RESET_ALL)
        sys.exit(1)
    return private_key


def main():
    print(f""" {Fore.RED}
     (((((((((((((((((((((((((((((((((((       (((((((((((((((((((((((((((((((((((
     (((((((((((((((((((((((((((((((((((       (((((((((((((((((((((((((((((((((((
     (((((((((((((((((((((((((((((((((((       (((((((((((((((((((((((((((((((((((
     (((((((((((((((((((((((((((((((((((       (((((((((((((((((((((((((((((((((((



     (((((((((((((((((((((((((((                       (((((((((((((((((((((((((((
     (((((((((((((((((((((((((((((((               (((((((((((((((((((((((((((((((
     (((((((((((((((((((((((((((((((((           (((((((((((((((((((((((((((((((((
     ((((((((((((((((((((((((((((((((((         ((((((((((((((((((((((((((((((((((
                         (((((((((((((((       (((((((((((((((
                            ((((((((((((       ((((((((((((
                             (((((((((((       (((((((((((
                             (((((((((((       (((((((((((
                             (((((((((((       (((((((((((
                             (((((((((((       (((((((((((
                             (((((((((((       (((((((((((
    {Style.RESET_ALL}
     EncryptDecrypt Tool
     Generated by: FuelFoundry
     Developer info at: https://fuelfoundry.io
     Code Release: 1.0
     All rights reserved

     Use at your own risk, no warranties provided.

     "A chain is never stronger than its weakest link" -T. Reid
     -----------------------------------------------------------------------------""" + Style.RESET_ALL)

    print("\nSelect an option:")
    print(Fore.LIGHTBLUE_EX + "     1. Encrypt a Private Key")
    print(Fore.LIGHTBLUE_EX + "     2. Decrypt an Encrypted Private Key\n" + Style.RESET_ALL)
    choice = input("Enter 1 or 2: " + Style.RESET_ALL).strip()

    if choice == '1':
        # encryption process
        private_key = get_private_key_input()

        while True:
            password = getpass.getpass("\nEnter encryption password (min 12 characters): " + Style.RESET_ALL)
            if len(password) < 12:
                print(Fore.RED + "Password must be at least 12 characters long. Please try again." + Style.RESET_ALL)
                continue
            password_confirm = getpass.getpass("Confirm encryption password: " + Style.RESET_ALL)
            if password != password_confirm:
                print(Fore.RED + "Passwords do not match. Please try again.\n" + Style.RESET_ALL)
            else:
                break

        print(Fore.LIGHTMAGENTA_EX + "\nProcessing... (this may take a few seconds to a minute)\n" + Style.RESET_ALL)
        encrypted_output = encrypt_private_key(private_key, password)
        print(
            Fore.LIGHTBLUE_EX + "--- Encrypted Output (do not copy this line, copy only the text below) ---" + Style.RESET_ALL)
        print(Fore.RED + encrypted_output + Style.RESET_ALL)
        print(
            Fore.LIGHTBLUE_EX + "---- Encryption End (do not copy this line, copy only the text above) ---\n" + Style.RESET_ALL)
        print("Copy and paste this encrypted string into your KeyVault." + Style.RESET_ALL)
        print("For security reasons, it is advised that you clear your screen and exit this terminal.\n" + Style.RESET_ALL)

    elif choice == '2':
        # decryption process
        encrypted_str = getpass.getpass("Enter the encrypted string (input hidden): " + Style.RESET_ALL).strip()
        if not encrypted_str:
            print(Fore.RED + "Encrypted string cannot be empty." + Style.RESET_ALL)
            sys.exit(1)

        password = getpass.getpass("Enter decryption password (input hidden): " + Style.RESET_ALL)
        print(Fore.LIGHTMAGENTA_EX + "\nProcessing... (this may take a few seconds to a minute)" + Style.RESET_ALL)

        decrypted_private_key = decrypt_private_key(encrypted_str, password)
        print(Fore.LIGHTBLUE_EX + "\n--- Decrypted Private Key ---" + Style.RESET_ALL)
        print(Fore.RED + decrypted_private_key + Style.RESET_ALL)
        print(Fore.LIGHTBLUE_EX + "-----------------------------\n" + Style.RESET_ALL)
        print("For security reasons, it is advised that you clear your screen and exit this terminal.\n" + Style.RESET_ALL)

    else:
        print(Fore.RED + "Invalid choice. Please run the script again and select either 1 or 2." + Style.RESET_ALL)
        sys.exit(1)


if __name__ == "__main__":
    main()
