import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


with open("receiver_privatekey.pem", "rb") as f:
    receiver_priv = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

print("[OK] Receiver private key loaded")


ephemeral_pub_b64 = input("ephemeral_pub_b64: ")
nonce_b64 = input("nonce_b64: ")
ciphertext_b64 = input("ciphertext_b64: ")

# Decode base64 → bytes
ephemeral_pub_bytes = base64.b64decode(ephemeral_pub_b64)
nonce = base64.b64decode(nonce_b64)
ciphertext = base64.b64decode(ciphertext_b64)


ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(),
    ephemeral_pub_bytes
)

print("[OK] Ephemeral public key converted")


shared_secret = receiver_priv.exchange(ec.ECDH(), ephemeral_pub)
print("[OK] Shared secret computed")


hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data"
)
aes_key = hkdf.derive(shared_secret)

print("[OK] AES key derived")


aesgcm = AESGCM(aes_key)

try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    print(" PESAN BERHASIL DIDECRYPT")
    print("\n Plaintext:", plaintext.decode())

except Exception as e:
    print(" ERROR decrypt:", str(e))
