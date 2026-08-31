from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

PRIVATE_KEY_FILE = BASE_DIR / "private_key.pem"
PUBLIC_KEY_FILE = BASE_DIR / "public_key.pem"


# ============================================================
# GENERATE RSA KEY PAIR
# ============================================================

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


# ============================================================
# SAVE PRIVATE KEY
# ============================================================

private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

PRIVATE_KEY_FILE.write_bytes(private_bytes)


# ============================================================
# EXTRACT PUBLIC KEY
# ============================================================

public_key = private_key.public_key()


public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

PUBLIC_KEY_FILE.write_bytes(public_bytes)


# ============================================================
# RESULT
# ============================================================

print("=" * 60)
print("RSA KEY PAIR GENERATED")
print("=" * 60)

print()
print(f"Private key: {PRIVATE_KEY_FILE}")
print(f"Public key : {PUBLIC_KEY_FILE}")

print()
print("Algorithm : RSA")
print("Key size  : 2048 bits")
print()
print("IMPORTANT:")
print("Keep private_key.pem secret.")
print("The verifier only needs public_key.pem.")