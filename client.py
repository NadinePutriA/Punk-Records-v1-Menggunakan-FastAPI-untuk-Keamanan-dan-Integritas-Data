# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API

from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

os.makedirs("client", exist_ok = True)

# TODO: Lengkapi proses-proses pembuatan private dan public key
# untuk users yang disimulasikan
priv_key = ec.generate_private_key(ec.SECP256R1())
with open("client/client_privatekey.pem", "wb") as f:
    f.write(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

pub_key = priv_key.public_key()
with open("client/client_publickey.pem", "wb") as f:
    f.write(
        pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Public & private key berhasil dibuat dan disimpan di folder client")

#TODO: Pembuatan message + signature 
message = b"Ini pesan rahasia dari client."

signature = priv_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

print("Pesan:", message)
print("Signature:", signature.hex())

with open("client/signature.hex", "w") as f:
    f.write(signature.hex())

print("Signature disimpan di client/signature.hex")


#  tanda tangan file PDF
from cryptography.hazmat.primitives import hashes

pdf_path = "document.pdf"   

if os.path.exists(pdf_path):
    print("\nMENANDATANGANI PDF")

    # Baca file PDF
    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    # Hash PDF
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_data)
    pdf_hash = digest.finalize()

    # Tanda tangan hash PDF (ECDSA-SHA256)
    pdf_signature = priv_key.sign(
        pdf_hash,
        ec.ECDSA(hashes.SHA256())
    )

    # Simpan signature PDF ke file
    with open("client/pdf_signature.hex", "w") as f:
        f.write(pdf_signature.hex())

    print("PDF berhasil ditandatangani!")
    print("Signature PDF disimpan di client/pdf_signature.hex")
else:
    print("\n File document.pdf tidak ditemukan. Lewati tanda tangan PDF.")


# TODO: Bagian enkripsi simetrik
# AES-256 CBC encryption
# Key = 32 byte, IV = 16 byte

aes_key = os.urandom(32)   
iv = os.urandom(16)        

# Padding untuk AES (harus kelipatan 16 byte)
pad_len = 16 - (len(message) % 16)
padded_message = message + bytes([pad_len]) * pad_len

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()

ciphertext = encryptor.update(padded_message) + encryptor.finalize()


with open("client/encrypted_message.hex", "w") as f:
    f.write(ciphertext.hex())

print("AES Encryption")
print("AES key (hex):", aes_key.hex())
print("IV (hex):", iv.hex())
print("Ciphertext (hex):", ciphertext.hex())
print("Encrypted message disimpan di client/encrypted_message.hex")


with open("client/aes_key.hex", "w") as f:
    f.write(aes_key.hex())

with open("client/iv.hex", "w") as f:
    f.write(iv.hex())

print("AES key dan IV disimpan di client/")