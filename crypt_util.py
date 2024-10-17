"""
The University of Adelaide - Semester 2, 2024
Secure Programming Advanced Course Assignment - Secure Chat System
Group Name: Group 1
Authors: Bishal Adhikari, Den Tit Vityia Meas, Se Jin Yoon, Victor Li 
"""

"""crypt_util.py
Helper functions regarding cryptography used in the Olaf-Neighbourhood protocol

Module Includes:
    - Signing & Verifying
    - Encrypting & Decrypting
    - Encoding & Decoding

From the Olaf-Neighbourhood Protocol documentation:
RSA Key Pair Generation for signing & verification
- Key size: 2048 bits
- Public exponent: 65537
- Padding scheme: RSA-PSS with SHA-256
- Salt length: 32 bytes   (For signing/verifying)
- Public key format: PEM encoding, SPKI format
    
Asymmetric encryption and decryption is performed with RSA: 
- Key size/Modulus length (n) = 2048 bits 
- Public exponent (e) = 65537 
- Padding scheme: OAEP with SHA-256 digest/hash function 
- Public keys are exported in PEM encoding with SPKI format.

Symmetric encryption is performed with AES in GCM mode: 
- Initialisation vector (IV) = 16 bytes (Must be randomly generated) 
- Additional/associated data = not used (empty). 
- Key length: 16 bytes (128 bits)
- Authentication tag: 16 bytes (128 bits). 
  The authentication tag takes up the final 128 bits of the ciphertext.
"""

import os
import base64
from datetime import datetime
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


# RSA Key Generation (Used for encrypting/decrypting and signing/verifying)
def generate_rsa_keypair():
    """
    Generate an RSA key pair and store them in local storage.

    The private key is generated with the following parameters:
        - Key size (n): 2048 bits
        - Public exponent (e): 65537

    The private key is stored in PEM format, PKCS#8 structure (PrivateKeyInfo),
    and the public key is stored in PEM format, PKCS#1 structure (SubjectPublicKeyInfo).

    Returns:
        tuple: A tuple containing:
            - str: Path to the stored private key file.
            - str: Path to the stored public key file.
    """
    key = RSA.generate(bits=2048, e=65537)  # Generate Private Key
    private_key = key.export_key(format='PEM', pkcs=8)

    # Export public key in SPKI format
    public_key = key.publickey().export_key(format='PEM')  # Export in SPKI format by default
    
    # Set names for key_pair folder, and both private & public key_file
    key_pair_folder_name = f"my_key_pair_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    private_key_file_name = 'my_private_key.pem'
    public_key_file_name = 'my_public_key.pem'
    
    # Set paths to keys
    private_key_path = os.path.join(key_pair_folder_name, private_key_file_name)
    public_key_path = os.path.join(key_pair_folder_name, public_key_file_name)

    # Create the folder if it doesn't exist
    if not os.path.exists(key_pair_folder_name):
        os.makedirs(key_pair_folder_name)

    # Save private key to a file (optional)
    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    # Save public key to a file (optional)
    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    return private_key_path, public_key_path


# Import private or public key from a .pem local key file path
def import_key(key_pem):
    """
    Import a private or public RSA key from a PEM file or bytes.

    Args:
        key_pem (str or bytes): The file path to a .pem key file or the PEM key in bytes.

    Returns:
        RSA.RsaKey: The RSA key object.

    Raises:
        ValueError: If the key format is invalid or cannot be read.
    """
    # Check if key_pem is passed in as file_path containing .pem key file
    if isinstance(key_pem, str) and key_pem.endswith('.pem'):
        with open(key_pem, 'rb') as key_file:
            key = RSA.import_key(key_file.read())    
    elif isinstance(key_pem, bytes):  # If passed in .pem key in bytes
        key = RSA.import_key(key_pem)
    return key  # Return RSA Key Object


# Export Private Key in PEM format, PKCS#8 structure (PrivateKeyInfo)
def export_private_key(private_key):
    """
    Export the private RSA key in PEM format.

    Args:
        private_key (RSA.RsaKey): The RSA private key to be exported.

    Returns:
        bytes: The PEM-encoded private key.
    """
    return private_key.export_key(format='PEM', pkcs=8)


# Export Public Key in PEM format, PKCS#1 structure (SubjectPublicKeyInfo)
def export_public_key(public_key):
    """
    Export the public RSA key in PEM format.

    Args:
        public_key (RSA.RsaKey): The RSA public key to be exported.

    Returns:
        bytes: The PEM-encoded public key.
    """
    return public_key.export_key(format='PEM')


# Signing message with RSA-PSS and SHA-256 with 32-bytes Salt Length
def get_signature(message, private_key):
    """
    Generate a digital signature for a given message using RSA-PSS and SHA-256.

    Args:
        message (str): The message to be signed.
        private_key (RSA.RsaKey or str): The RSA private key to sign with, or the file path to the key.

    Returns:
        str: The base64-encoded digital signature.

    Raises:
        ValueError: If the private key is invalid or signing fails.
    """
    if not isinstance(private_key, RSA.RsaKey):
        rsa_key = import_key(private_key)
    else:
        rsa_key = private_key
    
    if isinstance(message, str):
        message = message.encode('utf-8')

    h = SHA256.new(message)  # Hash with SHA-256
    signature = pss.new(rsa_key, salt_bytes=32).sign(h)
    return base64.b64encode(signature).decode('utf-8')


# Verifying message with RSA-PSS and SHA-256 with 32-bytes Salt Length
def is_signature_valid(message, signature, public_key):
    """
    Verify a digital signature for a given message using RSA-PSS and SHA-256.

    Args:
        message (str): The original message that was signed.
        signature (str): The base64-encoded digital signature to verify.
        public_key (RSA.RsaKey or str): The RSA public key to verify against, or the file path to the key.

    Returns:
        bool: True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the public key is invalid or verification fails.
    """
    if not isinstance(public_key, RSA.RsaKey):
        rsa_key = import_key(public_key)
    else:
        rsa_key = public_key

    if isinstance(message, str):
        message = message.encode('utf-8')

    h = SHA256.new(message)  # Hash with SHA-256
    verifier = pss.new(rsa_key, salt_bytes=32)

    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except ValueError:
        return False


# RSA Encryption
def rsa_encrypt(public_key, data):
    """
    Encrypt data using the RSA public key.

    Args:
        public_key (RSA.RsaKey or str): The RSA public key for encryption, or the file path to the key.
        data (str): The plaintext data to be encrypted.

    Returns:
        str: The base64-encoded encrypted data.

    Raises:
        ValueError: If the public key is invalid or encryption fails.
    """
    if not isinstance(public_key, RSA.RsaKey):
        rsa_key = import_key(public_key)
    else:
        rsa_key = public_key

    if isinstance(data, str):
        data = data.encode('utf-8')

    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')


# RSA Decryption
def rsa_decrypt(private_key, encrypted_data):
    """
    Decrypt data using the RSA private key.

    Args:
        private_key (RSA.RsaKey or str): The RSA private key for decryption, or the file path to the key.
        encrypted_data (str): The base64-encoded encrypted data to be decrypted.

    Returns:
        str: The decrypted plaintext data.

    Raises:
        ValueError: If the private key is invalid or decryption fails.
    """
    if not isinstance(private_key, RSA.RsaKey):
        rsa_key = import_key(private_key)
    else:
        rsa_key = private_key

    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode('utf-8')


# AES key generation
def generate_aes_key():
    """
    Generate a random AES key.

    Returns:
        bytes: A 16-byte (128-bit) AES key.
    """
    return get_random_bytes(16)  # 16 bytes = 128 bits


# AES Encryption
def aes_encrypt(key, plaintext):
    """
    Encrypt a plaintext message using AES-GCM.

    Args:
        key (bytes): The AES key for encryption (must be 16 bytes for AES-128).
        plaintext (str): The plaintext message to be encrypted.

    Returns:
        tuple: A tuple containing:
            - str: Base64-encoded IV (nonce).
            - str: Base64-encoded combined ciphertext and authentication tag.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    combined = ciphertext + tag  # The last 16 bytes will be the tag
    iv = cipher.nonce  # The nonce is used as the IV in GCM
    return (
        base64.b64encode(iv).decode('utf-8'),
        base64.b64encode(combined).decode('utf-8')
    )


# AES Decryption
def aes_decrypt(key, iv, combined):
    """
    Decrypt a combined ciphertext and authentication tag using AES-GCM.

    Args:
        key (bytes): The AES key for decryption (must be the same as used for encryption).
        iv (str): Base64-encoded IV (nonce) used during encryption.
        combined (str): Base64-encoded combined ciphertext and authentication tag.

    Returns:
        str: The decrypted plaintext message.

    Raises:
        ValueError: If the decryption fails due to a tag mismatch or other issues.
    """
    iv = base64.b64decode(iv)
    combined = base64.b64decode(combined)

    # Extract the tag from the last 16 bytes
    tag = combined[-16:]  # The last 16 bytes are the authentication tag
    ciphertext = combined[:-16]  # The rest is the ciphertext

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Verify the tag
    return plaintext.decode('utf-8')
