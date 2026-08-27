import csv
import random
from pathlib import Path


# -----------------------------------------
# PROJECT PATHS
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

DATA_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = DATA_DIR / "security_events_v3.csv"


# -----------------------------------------
# DATASET
# -----------------------------------------

rows = []


# -----------------------------------------
# NORMAL EVENTS
# -----------------------------------------

for _ in range(700):

    failed_attempts = random.randint(0, 5)

    verification_frequency = random.randint(1, 25)

    verification_result = random.choices(
        [1, 0],
        weights=[85, 15]
    )[0]

    key_size = random.choice(
        [2048, 3072, 4096]
    )

    algorithm = random.choices(
        ["RSA-PSS", "RSA-PKCS1v15"],
        weights=[80, 20]
    )[0]

    hour = random.randint(6, 22)

    rows.append({
        "verification_result": verification_result,
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

    failed_attempts = random.randint(1, 8)

    verification_frequency = random.randint(5, 30)

    verification_result = random.choices(
        [1, 0],
        weights=[20, 80]
    )[0]

    key_size = random.choice(
        [2048, 3072, 4096]
    )

    algorithm = random.choices(
        ["RSA-PSS", "RSA-PKCS1v15"],
        weights=[60, 40]
    )[0]

    hour = random.randint(0, 23)

    rows.append({
        "verification_result": verification_result,
        "failed_attempts": failed_attempts,
        "verification_frequency": verification_frequency,
        "key_size": key_size,
        "algorithm": algorithm,
        "hour": hour,
        "threat": 1
    })


# -----------------------------------------
# WRITE CSV
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


with open(OUTPUT_FILE, "w", newline="") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)


print("Day 2 dataset created successfully.")
print("Total records:", len(rows))
print("Saved to:", OUTPUT_FILE)