from pathlib import Path

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

OUTPUT_FILE = (
    Path(__file__).resolve().parent
    / "selectkbest_comparison.csv"
)


# ============================================================
# 2. SETTINGS
# ============================================================

RANDOM_SEED = 42

K = 7


# ============================================================
# 3. FEATURES
# ============================================================

ALL_FEATURES = [
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

TARGET = "threat"


# ============================================================
# 4. QI SELECTED FEATURES
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


# ============================================================
# 5. LOAD DATA
# ============================================================

print("=" * 70)
print("SELECTKBEST VS QUANTUM-INSPIRED FEATURE SELECTION")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset:", DATA_FILE)
print("Shape:", data.shape)


# ============================================================
# 6. CHECK DATA
# ============================================================

missing_columns = [
    column
    for column in ALL_FEATURES + [TARGET]
    if column not in data.columns
]

if missing_columns:

    print("\nERROR: Missing columns:")

    for column in missing_columns:
        print(" -", column)

    raise SystemExit(1)


X = data[ALL_FEATURES].copy()

y = data[TARGET].copy()


# ============================================================
# 7. SAME TRAIN / VALIDATION / TEST SPLIT
# ============================================================

X_temp, X_test, y_temp, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_SEED,
    stratify=y
)

X_train, X_validation, y_train, y_validation = train_test_split(
    X_temp,
    y_temp,
    test_size=0.25,
    random_state=RANDOM_SEED,
    stratify=y_temp
)


print("\nData split:")

print("Training   :", X_train.shape)
print("Validation :", X_validation.shape)
print("Final Test :", X_test.shape)


# ============================================================
# 8. PREPROCESS NUMERIC FEATURES FOR SELECTKBEST
# ============================================================
#
# SelectKBest with ANOVA F-test requires numeric input.
#
# We encode the categorical "algorithm" feature first.
# ============================================================

categorical_features = ["algorithm"]

numeric_features = [
    feature
    for feature in ALL_FEATURES
    if feature != "algorithm"
]


preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            categorical_features
        ),
        (
            "numeric",
            "passthrough",
            numeric_features
        )
    ]
)


# ============================================================
# 9. FIT PREPROCESSOR ON TRAINING DATA ONLY
# ============================================================

X_train_encoded = preprocessor.fit_transform(
    X_train
)

X_validation_encoded = preprocessor.transform(
    X_validation
)

X_test_encoded = preprocessor.transform(
    X_test
)


# Get encoded feature names

feature_names = (
    preprocessor
    .get_feature_names_out()
)


# ============================================================
# 10. SELECT K BEST FEATURES
# ============================================================

print("\n")
print("=" * 70)
print("SELECTKBEST FEATURE SELECTION")
print("=" * 70)


selector = SelectKBest(
    score_func=f_classif,
    k=K
)


X_train_selected = selector.fit_transform(
    X_train_encoded,
    y_train
)

X_validation_selected = selector.transform(
    X_validation_encoded
)

X_test_selected = selector.transform(
    X_test_encoded
)


selected_mask = selector.get_support()

selected_encoded_features = [
    feature_names[i]
    for i, selected
    in enumerate(selected_mask)
    if selected
]


print("\nSelectKBest selected features:")

for feature in selected_encoded_features:

    print(" -", feature)


# ============================================================
# 11. TRAIN SELECTKBEST MODEL
# ============================================================

print("\nTraining SelectKBest model...")


selectkbest_model = RandomForestClassifier(
    n_estimators=150,
    random_state=RANDOM_SEED,
    class_weight="balanced"
)


selectkbest_model.fit(
    X_train_selected,
    y_train
)


# ============================================================
# 12. SELECTKBEST FINAL TEST
# ============================================================

selectkbest_predictions = (
    selectkbest_model.predict(
        X_test_selected
    )
)


selectkbest_probabilities = (
    selectkbest_model.predict_proba(
        X_test_selected
    )[:, 1]
)


selectkbest_accuracy = accuracy_score(
    y_test,
    selectkbest_predictions
)

selectkbest_precision = precision_score(
    y_test,
    selectkbest_predictions,
    zero_division=0
)

selectkbest_recall = recall_score(
    y_test,
    selectkbest_predictions,
    zero_division=0
)

selectkbest_f1 = f1_score(
    y_test,
    selectkbest_predictions,
    zero_division=0
)

selectkbest_roc_auc = roc_auc_score(
    y_test,
    selectkbest_probabilities
)


tn, fp, fn, tp = confusion_matrix(
    y_test,
    selectkbest_predictions
).ravel()


selectkbest_fpr = (
    fp / (fp + tn)
)

selectkbest_fnr = (
    fn / (fn + tp)
)


# ============================================================
# 13. DISPLAY SELECTKBEST RESULTS
# ============================================================

print("\n")
print("=" * 70)
print("SELECTKBEST FINAL TEST RESULTS")
print("=" * 70)


print(
    "Accuracy :",
    round(selectkbest_accuracy, 4)
)

print(
    "Precision:",
    round(selectkbest_precision, 4)
)

print(
    "Recall   :",
    round(selectkbest_recall, 4)
)

print(
    "F1       :",
    round(selectkbest_f1, 4)
)

print(
    "ROC-AUC  :",
    round(selectkbest_roc_auc, 4)
)

print(
    "FPR      :",
    round(selectkbest_fpr, 4)
)

print(
    "FNR      :",
    round(selectkbest_fnr, 4)
)


print("\nConfusion Matrix:")

print(
    f"TN={tn}  FP={fp}"
)

print(
    f"FN={fn}  TP={tp}"
)


# ============================================================
# 14. COMPARISON WITH QI RESULTS
# ============================================================
#
# These are the previously measured QI results.
#
# We are NOT retraining the QI optimizer here.
# ============================================================

QI_ACCURACY = 0.9650
QI_PRECISION = 0.9730
QI_RECALL = 0.9754
QI_F1 = 0.9742
QI_ROC_AUC = 0.9944
QI_FPR = 0.0570
QI_FNR = 0.0246


# ============================================================
# 15. FINAL COMPARISON
# ============================================================

comparison = pd.DataFrame(
    [

        {
            "method":
                "Classical SelectKBest",

            "feature_count":
                K,

            "accuracy":
                selectkbest_accuracy,

            "precision":
                selectkbest_precision,

            "recall":
                selectkbest_recall,

            "f1":
                selectkbest_f1,

            "roc_auc":
                selectkbest_roc_auc,

            "false_positive_rate":
                selectkbest_fpr,

            "false_negative_rate":
                selectkbest_fnr
        },

        {
            "method":
                "Quantum-Inspired",

            "feature_count":
                len(QI_FEATURES),

            "accuracy":
                QI_ACCURACY,

            "precision":
                QI_PRECISION,

            "recall":
                QI_RECALL,

            "f1":
                QI_F1,

            "roc_auc":
                QI_ROC_AUC,

            "false_positive_rate":
                QI_FPR,

            "false_negative_rate":
                QI_FNR
        }

    ]
)


print("\n")
print("=" * 70)
print("CLASSICAL SELECTKBEST VS QUANTUM-INSPIRED")
print("=" * 70)


print(
    comparison.to_string(
        index=False
    )
)


# ============================================================
# 16. SAVE RESULTS
# ============================================================

comparison.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n")
print("=" * 70)
print("COMPARISON COMPLETE")
print("=" * 70)


print("\nResults saved to:")

print(OUTPUT_FILE)