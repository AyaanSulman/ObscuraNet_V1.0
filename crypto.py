import os
import logging
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
KEY_DIR = "keys"


def bootstrap_keys():
    """
    Ensure keys directory exists. If Fernet or X25519 keys are missing, generate them.
    """
    logger.debug("[crypto/bootstrap_keys] Entry")
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        logger.info("[crypto/bootstrap_keys] Created keys directory.")

    # 1) Fernet key
    fernet_path = os.path.join(KEY_DIR, "fernet.key")
    if not os.path.exists(fernet_path):
        key = Fernet.generate_key()
        try:
            with open(fernet_path, "wb") as f:
                f.write(key)
            logger.info("[crypto/bootstrap_keys] Generated new Fernet key.")
        except Exception as e:
            logger.error(f"[crypto/bootstrap_keys] Failed to write Fernet key: {e}")
    else:
        logger.debug("[crypto/bootstrap_keys] Fernet key already exists.")

    # 2) X25519 key pair
    priv_path = os.path.join(KEY_DIR, "x25519_private.key")
    pub_path = os.path.join(KEY_DIR, "x25519_public.key")
    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        try:
            priv = x25519.X25519PrivateKey.generate()
            priv_bytes = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(priv_path, "wb") as f:
                f.write(priv_bytes)

            pub = priv.public_key()
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            with open(pub_path, "wb") as f:
                f.write(pub_bytes)

            logger.info("[crypto/bootstrap_keys] Generated new X25519 key pair.")
        except Exception as e:
            logger.error(f"[crypto/bootstrap_keys] Failed to generate/write X25519 keys: {e}")
    else:
        logger.debug("[crypto/bootstrap_keys] X25519 key pair already exists.")


def load_x25519_private_key():
    """
    Load our X25519 private key from disk.
    """
    logger.debug("[crypto/load_x25519_private_key] Entry")
    priv_path = os.path.join(KEY_DIR, "x25519_private.key")
    try:
        with open(priv_path, "rb") as f:
            priv_bytes = f.read()
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        logger.debug("[crypto/load_x25519_private_key] Private key loaded.")
        return priv
    except Exception as e:
        logger.error(f"[crypto/load_x25519_private_key] Failed: {e}")
        raise


def load_x25519_public_key():
    """
    Load our X25519 public key from disk.
    """
    logger.debug("[crypto/load_x25519_public_key] Entry")
    pub_path = os.path.join(KEY_DIR, "x25519_public.key")
    try:
        with open(pub_path, "rb") as f:
            pub_bytes = f.read()
        pub = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        logger.debug("[crypto/load_x25519_public_key] Public key loaded.")
        return pub
    except Exception as e:
        logger.error(f"[crypto/load_x25519_public_key] Failed: {e}")
        raise


def get_x25519_pubkey_b64():
    """
    Return our X25519 public key as a base64‐encoded string.
    """
    logger.debug("[crypto/get_x25519_pubkey_b64] Entry")
    pub = load_x25519_public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    b64 = base64.b64encode(raw).decode()
    logger.debug(f"[crypto/get_x25519_pubkey_b64] Public key (B64): {b64[:10]}…")
    return b64


def load_peer_x25519_pubkey_b64(pubkey_b64):
    """
    Given a base64‐encoded peer key, return an X25519PublicKey instance.
    """
    logger.debug(f"[crypto/load_peer_x25519_pubkey_b64] Entry: {pubkey_b64[:10]}…")
    try:
        raw = base64.b64decode(pubkey_b64.encode())
        key = x25519.X25519PublicKey.from_public_bytes(raw)
        logger.debug("[crypto/load_peer_x25519_pubkey_b64] Peer public key parsed.")
        return key
    except Exception as e:
        logger.error(f"[crypto/load_peer_x25519_pubkey_b64] Failed to parse peer key: {e}")
        raise


def derive_shared_key(peer_pubkey_bytes):
    """
    Perform ECDH between our private key and the peer’s X25519 public bytes.
    Returns a 32‐byte shared secret for ChaCha20.
    """
    logger.debug("[crypto/derive_shared_key] Entry")
    try:
        priv = load_x25519_private_key()
        shared = priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_pubkey_bytes)
        )
        logger.info("[crypto/derive_shared_key] Derived shared key.")
        return shared
    except Exception as e:
        logger.error(f"[crypto/derive_shared_key] Failed: {e}")
        raise


def chacha20_encrypt(msg: bytes, key: bytes):
    """
    Encrypt `msg` with ChaCha20-Poly1305. Return nonce || ciphertext||tag.
    """
    logger.debug(f"[crypto/chacha20_encrypt] Entry: message length={len(msg)}")
    try:
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, msg, associated_data=None)
        blob = nonce + ct
        logger.debug(f"[crypto/chacha20_encrypt] Encrypted length={len(blob)}")
        return blob
    except Exception as e:
        logger.error(f"[crypto/chacha20_encrypt] Encryption failed: {e}")
        raise


def chacha20_decrypt(ciphertext: bytes, key: bytes):
    """
    Decrypt a ChaCha20‐Poly1305 blob. Expects 12‐byte nonce + ciphertext||tag.
    """
    logger.debug(f"[crypto/chacha20_decrypt] Entry: ciphertext length={len(ciphertext)}")
    try:
        aead = ChaCha20Poly1305(key)
        nonce = ciphertext[:12]
        ct_and_tag = ciphertext[12:]
        plaintext = aead.decrypt(nonce, ct_and_tag, associated_data=None)
        logger.debug(f"[crypto/chacha20_decrypt] Decrypted length={len(plaintext)}")
        return plaintext
    except Exception as e:
        logger.error(f"[crypto/chacha20_decrypt] Decryption failed: {e}")
        raise


def load_fernet():
    """
    Load (or create) a Fernet key to handle session caching and dummy tags.
    """
    logger.debug("[crypto/load_fernet] Entry")
    fernet_path = os.path.join(KEY_DIR, "fernet.key")

    # Ensure the key directory exists
    os.makedirs(KEY_DIR, exist_ok=True)

    try:
        # Check if the Fernet key file exists
        if not os.path.exists(fernet_path):
            logger.info("[crypto/load_fernet] Fernet key file not found. Generating a new key.")
            key = Fernet.generate_key()
            with open(fernet_path, "wb") as f:
                f.write(key)
            logger.info("[crypto/load_fernet] New Fernet key generated and saved.")
        else:
            logger.info("[crypto/load_fernet] Fernet key file found.")

        # Load the Fernet key from the file
        with open(fernet_path, "rb") as f:
            key = f.read()
        logger.info("[crypto/load_fernet] Fernet key loaded.")
        return Fernet(key)
    except Exception as e:
        logger.error(f"[crypto/load_fernet] Failed to load or create Fernet key: {e}")
        raise