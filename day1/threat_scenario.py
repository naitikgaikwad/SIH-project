from digital_signature import (
    generate_keys,
    sign_message,
    verify_signature
)


# --------------------------------------------------
# 1. Generate cryptographic keys
# --------------------------------------------------

private_key, public_key = generate_keys()


# --------------------------------------------------
# 2. Legitimate document
# --------------------------------------------------

original_document = b"SIH26141 Project Report - Version 1"


# --------------------------------------------------
# 3. Sign the legitimate document
# --------------------------------------------------

signature = sign_message(
    private_key,
    original_document
)

print("Document signed successfully.")


# --------------------------------------------------
# 4. Verify legitimate document
# --------------------------------------------------

valid = verify_signature(
    public_key,
    original_document,
    signature
)

print("Original document verification:", valid)


# --------------------------------------------------
# 5. Simulate document modification
# --------------------------------------------------

modified_document = b"SIH26141 Project Report - Version 2"


print("\nDocument has been modified.")


# --------------------------------------------------
# 6. Verify modified document
# --------------------------------------------------

valid = verify_signature(
    public_key,
    modified_document,
    signature
)

print("Modified document verification:", valid)


# --------------------------------------------------
# 7. Generate security event
# --------------------------------------------------

if not valid:

    security_event = {
        "event_type": "SIGNATURE_VERIFICATION_FAILURE",
        "verification_result": "INVALID",
        "possible_threat": "DOCUMENT_TAMPERING",
        "signature_algorithm": "RSA-PSS",
        "hash_algorithm": "SHA-256",
        "key_size": 2048
    }

    print("\nSecurity Event:")
    print(security_event)