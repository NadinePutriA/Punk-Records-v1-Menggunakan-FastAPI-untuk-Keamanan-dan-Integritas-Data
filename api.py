import base64
import os
import secrets
from datetime import datetime
from typing import Optional, List
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

app = FastAPI(title="Security Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SESSIONS = {} 

def check_session(username: str, token: str) -> bool:
    """Simple check: token must match stored token for username."""
    return username in SESSIONS and SESSIONS[username] == token

@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def get_index() -> dict:
	return {
		"message": "Hello world! Please visit http://localhost:8080/docs for API UI."
	}

# Session start
@app.post("/session-start")
async def start_session(username: str):

    token = secrets.token_hex(16)
    SESSIONS[username] = token
    return {
        "success": True,
        "message": "Session berhasil dibuat",
        "username": username,
        "session_token": token
    }

# End Session
@app.post("/session-end")
async def end_session(username: str, session_token: str):

    if check_session(username, session_token):
        SESSIONS.pop(username, None)
        return {"success": True, "message": "Session diakhiri"}
    return {"success": False, "message": "Session tidak valid"}

#TODO:
# Lengkapi fungsi berikut untuk menerima unggahan, memeriksa keutuhan file, lalu
# menyimpan public key milik user siapa
# Tentukan parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/store")
async def store_pubkey(username: str, pubkey: UploadFile = File(...)):
    msg = None

    try:
        key_bytes = await pubkey.read()
        if len(key_bytes) == 0:
            raise Exception("Public key kosong")

        os.makedirs("pubkeys", exist_ok=True)

        filename = f"pubkeys/{username}_publickey.pem"
        with open(filename, "wb") as f:
            f.write(key_bytes)

        msg = f"Public key milik {username} berhasil disimpan"

    except Exception as e:
        msg = str(e)
    
    return {
        "message": msg,
        "saved_as": filename
    }
    
#TODO:
# Lengkapi fungsi berikut untuk menerima signature, menghitung signature dari "tampered message"
# Lalu kembalikan hasil perhitungan signature ke requester
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/verify")
async def verify(username: str, message: str, signature: str, session_token: str):
    msg = None
    
    if not check_session(username, session_token):
        return {"valid": False, "message": "Session tidak valid atau expired"}

    pubkey_path = f"pubkeys/{username}_publickey.pem"
    if not os.path.exists(pubkey_path):
        return {"valid": False, "message": f"Public key user '{username}' tidak ditemukan."}

    try:
        with open(pubkey_path, "rb") as f:
            pubkey = serialization.load_pem_public_key(f.read())

        message_bytes = message.encode()
        signature_bytes = bytes.fromhex(signature)

        # Verify signature (ECDSA)
        pubkey.verify(
            signature_bytes,
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        return {
            "valid": True,
            "message": "Signature valid.",
            "username": username,
            "received_message": message
        }

    except Exception as e:
        return {
            "valid": False,
            "message": f"Signature TIDAK valid: {str(e)}",
            "username": username
        }
    
    
#TODO:
# Lengkapi fungsi berikut untuk menerima pesan yang aman ke server, 
# untuk selanjutnya diteruskan ke penerima yang dituju (ditentukan oleh pengirim)
# Tentukan sendiri parameters fungsi yang diperlukan untuk kebutuhan ini
@app.post("/relay")
async def relay(sender: str, receiver: str, message: str, signature: str,session_token: str):
    msg = None

    if not check_session(sender, session_token):
        return {"success": False, "message": "Session tidak valid atau sudah expired"}

    sender_pub_path = f"pubkeys/{sender}_publickey.pem"
    if not os.path.exists(sender_pub_path):
        return {"success": False, "message": f"Public key pengirim '{sender}' tidak ditemukan."}

    try:
        with open(sender_pub_path, "rb") as f:
            sender_pub = serialization.load_pem_public_key(f.read())
    except Exception as e:
        return {"success": False, "message": f"Gagal memuat public key pengirim: {str(e)}"}

    # verify signature
    try:
        sender_pub.verify(
            bytes.fromhex(signature),
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        return {"success": False, "message": "Signature tidak valid. Relay dibatalkan.", "error": str(e)}

    # load receiver public key
    receiver_pub_path = f"pubkeys/{receiver}_publickey.pem"
    if not os.path.exists(receiver_pub_path):
        return {"success": False, "message": f"Public key penerima '{receiver}' tidak ditemukan."}

    try:
        with open(receiver_pub_path, "rb") as f:
            receiver_pub = serialization.load_pem_public_key(f.read())
    except Exception as e:
        return {"success": False, "message": f"Gagal memuat public key penerima: {str(e)}"}

    # ephemeral ECDH key pair (server-side)
    try:
        ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pub = ephemeral_priv.public_key()
        ephemeral_pub_bytes = ephemeral_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    except Exception as e:
        return {"success": False, "message": f"Error membuat ephemeral key: {str(e)}"}

    # compute shared secret
    try:
        shared_secret = ephemeral_priv.exchange(ec.ECDH(), receiver_pub)
    except Exception as e:
        return {"success": False, "message": "Error computing shared key.", "error": str(e)}

    # derive AES-256 key via HKDF
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data"
        )
        aes_key = hkdf.derive(shared_secret)
    except Exception as e:
        return {"success": False, "message": f"Error deriving AES key: {str(e)}"}

    # encrypt with AES-GCM
    try:
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    except Exception as e:
        return {"success": False, "message": f"Error encrypting message: {str(e)}"}

    # return base64 encoded outputs
    try:
        out = {
            "success": True,
            "message": f"Pesan dari {sender} terenkripsi untuk {receiver} dan siap diteruskan.",
            "from": sender,
            "to": receiver,
            "ephemeral_pub_b64": base64.b64encode(ephemeral_pub_bytes).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode()
        }
        return out
    except Exception as e:
        return {"success": False, "message": f"Error preparing output: {str(e)}"}


from cryptography.hazmat.primitives import hashes

@app.post("/sign-pdf")
async def sign_pdf(username: str, session_token: str, signature: str, file: UploadFile = File(...)):
    # Cek session token
    if not check_session(username, session_token):
        return {"success": False, "message": "Session tidak valid atau expired."}

    # Cek keberadaan public key user
    pubkey_path = f"pubkeys/{username}_publickey.pem"
    if not os.path.exists(pubkey_path):
        return {"success": False, "message": f"Public key user '{username}' tidak ditemukan."}

    # Load public key
    with open(pubkey_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())

    # Baca file PDF & hash
    pdf_bytes = await file.read()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pdf_bytes)
    pdf_hash = digest.finalize()

    # Convert signature hex ke bytes
    try:
        sig_bytes = bytes.fromhex(signature)
    except:
        return {"success": False, "message": "Signature tidak valid (bukan HEX)."}

    # Verifikasi digital signature
    try:
        pubkey.verify(
            sig_bytes,
            pdf_hash,
            ec.ECDSA(hashes.SHA256())
        )
    except Exception as e:
        return {"success": False, "message": "Signature PDF TIDAK valid.", "error": str(e)}

    # Simpan PDF bertanda tangan
    os.makedirs("signed_pdf", exist_ok=True)
    outfile = f"signed_pdf/signed_{username}.pdf"

    with open(outfile, "wb") as f:
        f.write(pdf_bytes)

    return {
        "success": True,
        "message": "PDF berhasil ditandatangani secara digital.",
        "saved_as": outfile,
        "username": username
    }