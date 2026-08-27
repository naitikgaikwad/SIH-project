from digital_signature import (
    generate_keys,
    sign_message,
    verify_signature
)


# Generate keys
private_key, public_key = generate_keys()


# Original message
message = b"SIH26141 Digital Signature Test"


# Create signature
signature = sign_message(
    private_key,
    message
)

print("Signature created.")


# Verify original message
result = verify_signature(
    public_key,
    message,
    signature
)

print("Original verification:", result)


# Modify message
modified_message = b"SIH26141 Modified Test"


# Verify modified message
result = verify_signature(
    public_key,
    modified_message,
    signature
)

print("Modified verification:", result)