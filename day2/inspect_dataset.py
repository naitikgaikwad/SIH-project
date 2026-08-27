from pathlib import Path
import csv
import random
import pandas as pd


# ==================================================
# 1. PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"

DATA_DIR.mkdir(exist_ok=True)

DATA_FILE = DATA_DIR / "security_events_v3.csv"


# ==================================================
# 2. GENERATE DATASET
# ==================================================

rows = []


# ---------- NORMAL EVENTS ----------

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


# ---------- SUSPICIOUS EVENTS ----------

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


# ==================================================
# 3. SAVE DATASET
# ==================================================

fieldnames = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour",
    "threat"
]


with open(DATA_FILE, "w", newline="") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(rows)


print("\n========================================")
print("DATASET CREATED")
print("========================================")

print("Records:", len(rows))
print("File:", DATA_FILE)


# ==================================================
# 4. VERIFY FILE EXISTS
# ==================================================

if not DATA_FILE.exists():

    print("\nERROR: Dataset file was not created.")
    exit()


print("\nFile successfully verified.")


# ==================================================
# 5. LOAD DATASET
# ==================================================

data = pd.read_csv(DATA_FILE)


# ==================================================
# 6. INSPECT DATASET
# ==================================================

print("\n========================================")
print("FIRST 10 ROWS")
print("========================================")

print(data.head(10))


print("\n========================================")
print("DATASET SHAPE")
print("========================================")

print(data.shape)


print("\n========================================")
print("DATA TYPES")
print("========================================")

print(data.dtypes)


print("\n========================================")
print("MISSING VALUES")
print("========================================")

print(data.isnull().sum())


print("\n========================================")
print("THREAT DISTRIBUTION")
print("========================================")

print(data["threat"].value_counts())


print("\n========================================")
print("AVERAGE VALUES BY THREAT")
print("========================================")

print(
    data.groupby("threat")[
        [
            "verification_result",
            "failed_attempts",
            "verification_frequency",
            "key_size",
            "hour"
        ]
    ].mean()
)


print("\n========================================")
print("DAY 2 DATASET READY")
print("========================================")