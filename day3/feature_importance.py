from pathlib import Path

import pandas as pd
import joblib


# ==================================================
# PATHS
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_day3.pkl"
)


# ==================================================
# LOAD DATA AND MODEL
# ==================================================

data = pd.read_csv(DATA_FILE)

pipeline = joblib.load(MODEL_FILE)


# ==================================================
# ORIGINAL FEATURES
# ==================================================

features = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour",
    "signature_size",
    "certificate_valid",
    "source_frequency",
    "failed_verification_rate",
    "document_size",
    "metadata_anomaly",
    "replay_indicator",
    "key_age_days",
    "time_since_previous"
]


# ==================================================
# GET TRAINED RANDOM FOREST
# ==================================================

model = pipeline.named_steps["model"]

preprocessor = pipeline.named_steps[
    "preprocessing"
]


# ==================================================
# GET TRANSFORMED FEATURE NAMES
# ==================================================

feature_names = (
    preprocessor
    .get_feature_names_out()
)


importances = model.feature_importances_


# ==================================================
# CREATE RESULTS
# ==================================================

results = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
})


results = results.sort_values(
    by="importance",
    ascending=False
)


# ==================================================
# DISPLAY
# ==================================================

print("=" * 70)
print("DAY 3 FEATURE IMPORTANCE")
print("=" * 70)

print(
    results.to_string(
        index=False
    )
)


print("\n")
print("=" * 70)
print("TOP 10 FEATURES")
print("=" * 70)

print(
    results.head(10).to_string(
        index=False
    )
)


print("\n")
print("=" * 70)
print("FEATURE IMPORTANCE COMPLETE")
print("=" * 70)