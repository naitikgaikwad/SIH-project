from pathlib import Path

import numpy as np
import pandas as pd


# ==================================================
# PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)


# ==================================================
# RANDOM SEED
# ==================================================

np.random.seed(42)


# ==================================================
# NUMBER OF RECORDS
# ==================================================

N = 3000


# ==================================================
# BASIC SECURITY FEATURES
# ==================================================

verification_frequency = np.random.randint(
    1,
    36,
    size=N
)


# Failed attempts can NEVER exceed
# verification frequency.

failed_attempts = np.array([
    np.random.randint(
        0,
        frequency + 1
    )
    for frequency in verification_frequency
])


verification_result = np.random.choice(
    [0, 1],
    size=N,
    p=[0.25, 0.75]
)


key_size = np.random.choice(
    [1024, 2048, 3072, 4096],
    size=N,
    p=[0.05, 0.40, 0.30, 0.25]
)


algorithm = np.random.choice(
    [
        "RSA-PSS",
        "RSA-PKCS1v15"
    ],
    size=N
)


hour = np.random.randint(
    0,
    24,
    size=N
)


# ==================================================
# ADDITIONAL SECURITY FEATURES
# ==================================================

signature_size = np.random.randint(
    256,
    1025,
    size=N
)


certificate_valid = np.random.choice(
    [0, 1],
    size=N,
    p=[0.10, 0.90]
)


source_frequency = np.random.randint(
    1,
    51,
    size=N
)


# Correct failure rate

failed_verification_rate = (
    failed_attempts
    / verification_frequency
)


document_size = np.random.randint(
    10,
    5000,
    size=N
)


metadata_anomaly = np.random.choice(
    [0, 1],
    size=N,
    p=[0.85, 0.15]
)


replay_indicator = np.random.choice(
    [0, 1],
    size=N,
    p=[0.90, 0.10]
)


key_age_days = np.random.randint(
    1,
    2001,
    size=N
)


time_since_previous = np.random.randint(
    1,
    1001,
    size=N
)


# ==================================================
# SYNTHETIC THREAT MODEL
# ==================================================

risk_score = (

    # Invalid signature verification
    (verification_result == 0) * 3

    # Multiple failures
    + (failed_attempts >= 5) * 2

    # High verification activity
    + (verification_frequency >= 20) * 1

    # Invalid certificate
    + (certificate_valid == 0) * 3

    # Suspicious metadata
    + (metadata_anomaly == 1) * 2

    # Possible replay
    + (replay_indicator == 1) * 3

    # High failure rate
    + (failed_verification_rate >= 0.5) * 2

    # High source activity
    + (source_frequency >= 35) * 1

    # Weak key
    + (key_size == 1024) * 1
)


# ==================================================
# THREAT LABEL
# ==================================================

threat = (
    risk_score >= 4
).astype(int)


# ==================================================
# CREATE DATAFRAME
# ==================================================

data = pd.DataFrame({

    "verification_result":
        verification_result,

    "failed_attempts":
        failed_attempts,

    "verification_frequency":
        verification_frequency,

    "key_size":
        key_size,

    "algorithm":
        algorithm,

    "hour":
        hour,

    "signature_size":
        signature_size,

    "certificate_valid":
        certificate_valid,

    "source_frequency":
        source_frequency,

    "failed_verification_rate":
        failed_verification_rate,

    "document_size":
        document_size,

    "metadata_anomaly":
        metadata_anomaly,

    "replay_indicator":
        replay_indicator,

    "key_age_days":
        key_age_days,

    "time_since_previous":
        time_since_previous,

    "threat":
        threat
})


# ==================================================
# VALIDATION
# ==================================================

assert (
    data["failed_attempts"]
    <= data["verification_frequency"]
).all()


assert (
    data["failed_verification_rate"]
    >= 0
).all()


assert (
    data["failed_verification_rate"]
    <= 1
).all()


# ==================================================
# SAVE DATASET
# ==================================================

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


data.to_csv(
    OUTPUT_FILE,
    index=False
)


# ==================================================
# DISPLAY RESULTS
# ==================================================

print("=" * 70)
print("CORRECTED DAY 3 DATASET CREATED")
print("=" * 70)

print(
    "\nRecords:",
    len(data)
)


print(
    "\nDataset shape:",
    data.shape
)


print(
    "\nMaximum failed verification rate:",
    round(
        data[
            "failed_verification_rate"
        ].max(),
        4
    )
)


print(
    "\nMinimum failed verification rate:",
    round(
        data[
            "failed_verification_rate"
        ].min(),
        4
    )
)


print(
    "\nThreat distribution:"
)

print(
    data["threat"].value_counts()
)


print(
    "\nThreat percentage:"
)

print(
    data["threat"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)


print(
    "\nDataset validation:"
)

print(
    "Failed attempts <= verification frequency: PASS"
)

print(
    "Failure rate between 0 and 1: PASS"
)


print(
    "\nSaved to:"
)

print(
    OUTPUT_FILE
)


print(
    "\n" + "=" * 70
)