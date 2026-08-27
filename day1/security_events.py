import csv
import random
import os


os.makedirs("../data", exist_ok=True)

output_file = "../data/security_events.csv"

rows = []


# -----------------------------
# NORMAL EVENTS
# -----------------------------

for i in range(700):

    failed_attempts = random.randint(0, 2)
    verification_frequency = random.randint(1, 8)
    hour = random.randint(8, 18)

    rows.append({
        "verification_result": 1 if failed_attempts == 0 else 0,
        "failed_attempts": failed_attempts,
        "verification_frequency": verification_frequency,
        "key_size": random.choice([2048, 3072, 4096]),
        "algorithm": "RSA-PSS",
        "hour": hour,
        "source_id": random.randint(1, 50),
        "threat": 0
    })


# -----------------------------
# SUSPICIOUS EVENTS
# -----------------------------

for i in range(300):

    failed_attempts = random.randint(4, 15)
    verification_frequency = random.randint(15, 50)
    hour = random.choice([
        random.randint(0, 6),
        random.randint(20, 23)
    ])

    rows.append({
        "verification_result": 0,
        "failed_attempts": failed_attempts,
        "verification_frequency": verification_frequency,
        "key_size": random.choice([2048, 3072]),
        "algorithm": random.choice(["RSA-PSS", "RSA-PKCS1v15"]),
        "hour": hour,
        "source_id": random.randint(1, 50),
        "threat": 1
    })


# -----------------------------
# WRITE DATASET
# -----------------------------

fieldnames = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour",
    "source_id",
    "threat"
]


with open(output_file, "w", newline="") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)


print("Dataset created successfully.")
print("Total records:", len(rows))
print("Saved to:", output_file)