import hashlib


message1 = b"SIH26141 Digital Signature Test"
message2 = b"SIH26141 Modified Test"


hash1 = hashlib.sha256(message1).hexdigest()
hash2 = hashlib.sha256(message2).hexdigest()


print("Original message:")
print(message1.decode())

print("\nSHA-256:")
print(hash1)

print("\nModified message:")
print(message2.decode())

print("\nSHA-256:")
print(hash2)

print("\nHashes equal:", hash1 == hash2)