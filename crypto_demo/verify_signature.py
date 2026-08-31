from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DOCUMENT = BASE_DIR / "document.txt"
SIGNATURE = BASE_DIR / "signature.sig"
PUBLIC_KEY = BASE_DIR / "public_key.pem"


# ============================================================
# LOAD PUBLIC KEY
# ============================================================

with open(PUBLIC_KEY, "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )


# ============================================================
# READ DOCUMENT AND SIGNATURE
# ============================================================

document_data = DOCUMENT.read_bytes()
signature_data = SIGNATURE.read_bytes()


# ============================================================
# VERIFY DIGITAL SIGNATURE
# ============================================================

try:

    public_key.verify(
        signature_data,
        document_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("=" * 60)
    print("DIGITAL SIGNATURE VERIFICATION")
    print("=" * 60)
    print()
    print("Document : VALID")
    print("Signature: VALID")
    print("Algorithm: RSA-PSS")
    print("Hash     : SHA-256")
    print()
    print("AUTHENTICATION RESULT: VALID")
    print("=" * 60)


except Exception:

    print("=" * 60)
    print("DIGITAL SIGNATURE VERIFICATION")
    print("=" * 60)
    print()
    print("AUTHENTICATION RESULT: INVALID")
    print()
    print("The document does not match the supplied signature.")
    print("=" * 60)