import csv
import random
import os


os.makedirs("../data", exist_ok=True)

output_file = "../data/security_events_v2.csv"

rows = []


# -----------------------------------------
# NORMAL EVENTS
# -----------------------------------------

for _ in range(700):

    failed_attempts = random.choices(
        [0, 1, 2, 3, 4, 5],
        weights=[35, 25, 20, 10, 6, 4]
    )[0]

    verification_frequency = random.randint(1, 20)

    hour = random.randint(6, 22)

    algorithm = random.choices(
        ["RSA-PSS", "RSA-PKCS1v15"],
        weights=[85, 15]
    )[0]

    key_size = random.choice(
        [2048, 3072, 4096]
    )

    rows.append({
        "verification_result": 1 if failed_attempts <= 2 else 0,
        "failed_attempts": failed_attempts,
        "verification_frequency": verification_frequency,
        "key_size": key_size,
        "algorithm": algorithm,
        "hour": hour,
        "threat": 0
    })


# -----------------------------------------
# SUSPICIOUS EVENTS
# -----------------------------------------

for _ in range(300):

    failed_attempts = random.choices(
        [2, 3, 4, 5, 6, 7, 8, 10],
        weights=[5, 10, 15, 20, 20, 15, 10, 5]
    )[0]

    verification_frequency = random.randint(
        5, 35
    )

    hour = random.randint(
        0, 23
    )

    algorithm = random.choices(
        ["RSA-PSS", "RSA-PKCS1v15"],
        weights=[50, 50]
    )[0]

    key_size = random.choice(
        [1024, 2048, 3072]
    )

    rows.append({
        "verification_result": 0,
        "failed_attempts": failed_attempts,
        "verification_frequency": verification_frequency,
        "key_size": key_size,
        "algorithm": algorithm,
        "hour": hour,
        "threat": 1
    })


# -----------------------------------------
# WRITE DATASET
# -----------------------------------------

fieldnames = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour",
    "threat"
]


with open(output_file, "w", newline="") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)


print("Day 2 dataset created.")
print("Total records:", len(rows))
print("Saved to:", output_file)