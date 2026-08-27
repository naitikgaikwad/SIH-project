from pathlib import Path

import pandas as pd


# ==================================================
# PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)


# ==================================================
# LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)


print("=" * 70)
print("DAY 3 DATASET INSPECTION")
print("=" * 70)


# ==================================================
# BASIC INFORMATION
# ==================================================

print("\nDataset shape:")
print(data.shape)


print("\nColumns:")
print(list(data.columns))


# ==================================================
# FIRST 10 ROWS
# ==================================================

print("\nFirst 10 rows:")
print(data.head(10).to_string(index=False))


# ==================================================
# DATA TYPES
# ==================================================

print("\nData types:")
print(data.dtypes)


# ==================================================
# MISSING VALUES
# ==================================================

print("\nMissing values:")
print(data.isnull().sum())


# ==================================================
# THREAT DISTRIBUTION
# ==================================================

print("\nThreat distribution:")
print(data["threat"].value_counts())


print("\nThreat percentage:")
print(
    data["threat"]
    .value_counts(normalize=True)
    .mul(100)
    .round(2)
)


# ==================================================
# NUMERIC SUMMARY
# ==================================================

print("\nStatistical summary:")
print(
    data.describe().round(3).to_string()
)


# ==================================================
# AVERAGE VALUES BY THREAT
# ==================================================

print("\nAverage numeric values by threat:")

numeric_columns = data.select_dtypes(
    include="number"
).columns

print(
    data.groupby("threat")[numeric_columns]
    .mean()
    .round(3)
    .to_string()
)


# ==================================================
# ALGORITHM DISTRIBUTION
# ==================================================

print("\nAlgorithm distribution:")
print(
    pd.crosstab(
        data["algorithm"],
        data["threat"],
        margins=True
    )
)


# ==================================================
# VERIFICATION RESULT VS THREAT
# ==================================================

print("\nVerification result vs threat:")

print(
    pd.crosstab(
        data["verification_result"],
        data["threat"],
        margins=True
    )
)


# ==================================================
# REPLAY INDICATOR VS THREAT
# ==================================================

print("\nReplay indicator vs threat:")

print(
    pd.crosstab(
        data["replay_indicator"],
        data["threat"],
        margins=True
    )
)


# ==================================================
# METADATA ANOMALY VS THREAT
# ==================================================

print("\nMetadata anomaly vs threat:")

print(
    pd.crosstab(
        data["metadata_anomaly"],
        data["threat"],
        margins=True
    )
)


print("\n" + "=" * 70)
print("INSPECTION COMPLETE")
print("=" * 70)