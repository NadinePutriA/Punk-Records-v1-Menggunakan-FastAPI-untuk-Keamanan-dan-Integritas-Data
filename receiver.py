from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Generate private key
priv = ec.generate_private_key(ec.SECP256R1())

with open("receiver_privatekey.pem", "wb") as f:
    f.write(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Generate public key
pub = priv.public_key()

with open("receiver_publickey.pem", "wb") as f:
    f.write(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Receiver key selesai dibuat!")
