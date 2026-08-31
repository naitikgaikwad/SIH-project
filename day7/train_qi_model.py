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
    roc_auc_score
)

import joblib


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

MODEL_DIR = PROJECT_ROOT / "models"

MODEL_FILE = MODEL_DIR / "random_forest_qi_day7.pkl"


# ============================================================
# 2. QI-SELECTED FEATURES
# ============================================================

QI_FEATURES = [
    "verification_result",
    "failed_attempts",
    "certificate_valid",
    "source_frequency",
    "failed_verification_rate",
    "metadata_anomaly",
    "replay_indicator"
]

TARGET = "threat"


# ============================================================
# 3. SETTINGS
# ============================================================

RANDOM_SEED = 42


# ============================================================
# 4. LOAD DATA
# ============================================================

print("=" * 70)
print("DAY 7 - TRAIN QUANTUM-INSPIRED FEATURE MODEL")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset:", DATA_FILE)
print("Shape:", data.shape)


# ============================================================
# 5. CHECK REQUIRED COLUMNS
# ============================================================

required_columns = QI_FEATURES + [TARGET]

missing_columns = [
    column
    for column in required_columns
    if column not in data.columns
]

if missing_columns:

    print("\nERROR: Missing columns:")

    for column in missing_columns:
        print(" -", column)

    raise SystemExit(1)


# ============================================================
# 6. PREPARE DATA
# ============================================================

X = data[QI_FEATURES].copy()

y = data[TARGET].copy()


print("\nQI-selected features:")

for feature in QI_FEATURES:
    print(" -", feature)


print("\nTarget distribution:")
print(y.value_counts())


# ============================================================
# 7. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_SEED,
    stratify=y
)


print("\nData split:")

print("Training :", X_train.shape)
print("Test     :", X_test.shape)


# ============================================================
# 8. PREPROCESSING
# ============================================================

categorical_features = []

numeric_features = []


for feature in QI_FEATURES:

    if X[feature].dtype == "object":

        categorical_features.append(feature)

    else:

        numeric_features.append(feature)


transformers = []


if categorical_features:

    transformers.append(
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            categorical_features
        )
    )


if numeric_features:

    transformers.append(
        (
            "numeric",
            "passthrough",
            numeric_features
        )
    )


preprocessor = ColumnTransformer(
    transformers=transformers
)


# ============================================================
# 9. RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=150,
    random_state=RANDOM_SEED,
    class_weight="balanced"
)


pipeline = Pipeline(
    steps=[
        ("preprocessing", preprocessor),
        ("model", model)
    ]
)


# ============================================================
# 10. TRAIN
# ============================================================

print("\nTraining QI-selected Random Forest...")

pipeline.fit(
    X_train,
    y_train
)


# ============================================================
# 11. TEST
# ============================================================

predictions = pipeline.predict(
    X_test
)

probabilities = pipeline.predict_proba(
    X_test
)[:, 1]


# ============================================================
# 12. METRICS
# ============================================================

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


# ============================================================
# 13. DISPLAY RESULTS
# ============================================================

print("\n")
print("=" * 70)
print("QI MODEL TEST RESULTS")
print("=" * 70)

print(
    "Accuracy :",
    round(accuracy, 4)
)

print(
    "Precision:",
    round(precision, 4)
)

print(
    "Recall   :",
    round(recall, 4)
)

print(
    "F1       :",
    round(f1, 4)
)

print(
    "ROC-AUC  :",
    round(roc_auc, 4)
)


# ============================================================
# 14. SAVE MODEL
# ============================================================

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)


joblib.dump(
    pipeline,
    MODEL_FILE
)


print("\n")
print("=" * 70)
print("MODEL SAVED")
print("=" * 70)

print("\nModel:")

print(MODEL_FILE)

print("\nThe backend can now use this model.")