from pathlib import Path

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

import joblib


# ==================================================
# PROJECT PATH
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
# LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)

print("Dataset loaded.")
print("Records:", len(data))


# ==================================================
# FEATURES AND TARGET
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

X = data[features]

y = data["threat"]


# ==================================================
# TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==================================================
# FEATURE TYPES
# ==================================================

categorical_features = [
    "algorithm"
]

numeric_features = [
    feature
    for feature in features
    if feature not in categorical_features
]


# ==================================================
# PREPROCESSING
# ==================================================

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore"),
            categorical_features
        ),
        (
            "numeric",
            "passthrough",
            numeric_features
        )
    ]
)


# ==================================================
# RANDOM FOREST
# ==================================================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)


pipeline = Pipeline(
    steps=[
        ("preprocessing", preprocessor),
        ("model", model)
    ]
)


# ==================================================
# TRAIN
# ==================================================

pipeline.fit(
    X_train,
    y_train
)

print("\nModel training completed.")


# ==================================================
# PREDICTIONS
# ==================================================

predictions = pipeline.predict(X_test)

probabilities = pipeline.predict_proba(
    X_test
)[:, 1]


# ==================================================
# METRICS
# ==================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)


# ==================================================
# CONFUSION MATRIX
# ==================================================

tn, fp, fn, tp = confusion_matrix(
    y_test,
    predictions
).ravel()


false_positive_rate = fp / (fp + tn)

false_negative_rate = fn / (fn + tp)


# ==================================================
# RESULTS
# ==================================================

print("\n")
print("=" * 70)
print("DAY 3 RANDOM FOREST BASELINE")
print("=" * 70)

print(
    f"\nAccuracy           : {accuracy:.4f}"
)

print(
    f"Precision          : {precision:.4f}"
)

print(
    f"Recall             : {recall:.4f}"
)

print(
    f"F1 Score           : {f1:.4f}"
)

print(
    f"ROC-AUC            : {roc_auc:.4f}"
)


print("\nConfusion Matrix:")

print(
    f"TN = {tn}, FP = {fp}"
)

print(
    f"FN = {fn}, TP = {tp}"
)


print(
    f"\nFalse Positive Rate : "
    f"{false_positive_rate:.4f}"
)

print(
    f"False Negative Rate : "
    f"{false_negative_rate:.4f}"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions
    )
)


# ==================================================
# SAVE MODEL
# ==================================================

MODEL_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

joblib.dump(
    pipeline,
    MODEL_FILE
)

print("\nModel saved successfully.")

print("Model path:")
print(MODEL_FILE)