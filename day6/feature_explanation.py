import os
import joblib
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "models",
    "random_forest_day3.pkl"
)

DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "security_events_v3_extended.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "model_feature_explanation.csv"
)


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("DAY 6.5 - MODEL FEATURE EXPLANATION")
print("=" * 70)


# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(
        f"\nModel not found:\n{MODEL_FILE}"
    )

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(
        f"\nDataset not found:\n{DATA_FILE}"
    )


# ============================================================
# LOAD MODEL AND DATASET
# ============================================================

model = joblib.load(MODEL_FILE)
data = pd.read_csv(DATA_FILE)

print("\nModel loaded successfully.")
print(f"Dataset records: {len(data)}")


# ============================================================
# GET PREPROCESSING AND RANDOM FOREST
# ============================================================

preprocessor = model.named_steps["preprocessing"]
random_forest = model.named_steps["model"]


# ============================================================
# GET TRANSFORMED FEATURE NAMES
# ============================================================

feature_names = preprocessor.get_feature_names_out()

importances = random_forest.feature_importances_


# ============================================================
# CREATE FEATURE IMPORTANCE TABLE
# ============================================================

importance_df = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
})


importance_df = importance_df.sort_values(
    by="importance",
    ascending=False
).reset_index(drop=True)


# ============================================================
# DISPLAY ALL FEATURES
# ============================================================

print("\n")
print("=" * 70)
print("MODEL FEATURE IMPORTANCE")
print("=" * 70)

print(
    importance_df.to_string(index=False)
)


# ============================================================
# TOP 10 FEATURES
# ============================================================

top_features = importance_df.head(10)

print("\n")
print("=" * 70)
print("TOP 10 MODEL FEATURES")
print("=" * 70)

print(
    top_features.to_string(index=False)
)


# ============================================================
# SECURITY INTERPRETATION
# ============================================================

print("\n")
print("=" * 70)
print("SECURITY INTERPRETATION")
print("=" * 70)

print("""
The Random Forest relies more heavily on certain behavioral
and security-related features when distinguishing suspicious
events from normal events.

High-importance features indicate that the model uses those
features strongly during its learned decision process.

IMPORTANT:
Feature importance describes model behavior.
It does NOT prove that a feature causes a cyber threat.
""")


# ============================================================
# FEATURE-SPECIFIC INTERPRETATION
# ============================================================

print("=" * 70)
print("FEATURE INTERPRETATIONS")
print("=" * 70)

interpretations = {
    "verification_result":
        "Indicates whether digital signature verification succeeded.",

    "failed_attempts":
        "Represents the number of failed verification attempts.",

    "verification_frequency":
        "Measures how frequently verification activity occurs.",

    "key_size":
        "Represents the cryptographic key size used by the signature.",

    "hour":
        "Represents the hour at which the security event occurred.",

    "signature_size":
        "Represents the size of the digital signature.",

    "certificate_valid":
        "Indicates whether the associated certificate is valid.",

    "source_frequency":
        "Measures verification activity originating from the source.",

    "failed_verification_rate":
        "Represents the proportion of verification attempts that failed.",

    "document_size":
        "Represents the size of the signed document.",

    "metadata_anomaly":
        "Indicates suspicious or anomalous document metadata.",

    "replay_indicator":
        "Indicates whether replay-like activity was observed.",

    "key_age_days":
        "Represents the age of the signing key in days.",

    "time_since_previous":
        "Represents the time since the previous related event."
}


for _, row in top_features.iterrows():

    feature = row["feature"]

    # Remove preprocessing prefixes
    clean_feature = feature.replace(
        "numeric__",
        ""
    ).replace(
        "categorical__",
        ""
    )

    # Handle categorical algorithm features
    if clean_feature.startswith("algorithm_"):
        explanation = (
            "Represents the digital signature algorithm used."
        )
    else:
        explanation = interpretations.get(
            clean_feature,
            "Security-related feature used by the model."
        )

    print(
        f"\n{clean_feature}"
    )

    print(
        f"Importance: {row['importance']:.6f}"
    )

    print(
        f"Meaning: {explanation}"
    )


# ============================================================
# SAVE RESULTS
# ============================================================

importance_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# COMPLETE
# ============================================================

print("\n")
print("=" * 70)
print("FEATURE EXPLANATION COMPLETE")
print("=" * 70)

print("\nResults saved to:")
print(OUTPUT_FILE)