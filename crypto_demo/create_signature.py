from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DOCUMENT = BASE_DIR / "document_test2.txt"
PRIVATE_KEY = BASE_DIR / "private_key.pem"
PUBLIC_KEY = BASE_DIR / "public_key.pem"
SIGNATURE = BASE_DIR / "signature_test2.sig"


# ============================================================
# CHECK REQUIRED FILES
# ============================================================

if not DOCUMENT.exists():
    raise FileNotFoundError("document.txt not found.")

if not PRIVATE_KEY.exists():
    raise FileNotFoundError(
        "private_key.pem not found.\n"
        "A private key is required to create a signature."
    )


# ============================================================
# READ PRIVATE KEY
# ============================================================

with open(PRIVATE_KEY, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )


# ============================================================
# READ DOCUMENT
# ============================================================

document_data = DOCUMENT.read_bytes()


# ============================================================
# CREATE RSA-PSS SIGNATURE
# ============================================================

signature = private_key.sign(
    document_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)


# ============================================================
# SAVE SIGNATURE
# ============================================================

SIGNATURE.write_bytes(signature)


print("=" * 60)
print("DIGITAL SIGNATURE CREATED")
print("=" * 60)

print(f"Document : {DOCUMENT.name}")
print(f"Signature: {SIGNATURE.name}")
print("Algorithm: RSA-PSS")
print("Hash     : SHA-256")
print()
print(f"Saved to : {SIGNATURE}")