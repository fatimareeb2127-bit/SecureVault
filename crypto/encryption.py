import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAGIC = b"SV2"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000


def derive_key(password, salt):
    if not password:
        raise ValueError("Password is required.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    return kdf.derive(password.encode("utf8"))


def encrypt_data(data, password, metadata=None):
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    key = derive_key(password, salt)

    metadata = metadata or {}

    metadata_bytes = json.dumps(
        metadata,
        ensure_ascii=False
    ).encode("utf8")

    metadata_length = len(metadata_bytes)

    aad = MAGIC + metadata_length.to_bytes(4, "big")

    encrypted = AESGCM(key).encrypt(
        nonce,
        data,
        aad
    )

    package = (
        MAGIC +
        salt +
        nonce +
        metadata_length.to_bytes(4, "big") +
        metadata_bytes +
        encrypted
    )

    return package


def decrypt_data(package, password):

    minimum_size = (
        len(MAGIC) +
        SALT_SIZE +
        NONCE_SIZE +
        4 +
        16
    )

    if len(package) < minimum_size:
        raise ValueError("Invalid SecureVault package.")

    if not package.startswith(MAGIC):
        raise ValueError("Invalid SecureVault file.")

    position = len(MAGIC)

    salt = package[
        position:
        position + SALT_SIZE
    ]

    position += SALT_SIZE

    nonce = package[
        position:
        position + NONCE_SIZE
    ]

    position += NONCE_SIZE

    metadata_length = int.from_bytes(
        package[position:position + 4],
        "big"
    )

    position += 4

    if metadata_length < 0:
        raise ValueError("Invalid metadata.")

    if position + metadata_length > len(package):
        raise ValueError("Corrupted package.")

    metadata_bytes = package[
        position:
        position + metadata_length
    ]

    position += metadata_length

    try:
        metadata = json.loads(
            metadata_bytes.decode("utf8")
        )
    except Exception:
        metadata = {}

    aad = (
        MAGIC +
        metadata_length.to_bytes(4, "big")
    )

    key = derive_key(password, salt)

    decrypted = AESGCM(key).decrypt(
        nonce,
        package[position:],
        aad
    )

    return decrypted, metadata