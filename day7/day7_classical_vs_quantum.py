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
    / "classical_vs_quantum_results.csv"
)


# ============================================================
# 2. RANDOM SEED
# ============================================================

RANDOM_SEED = 42


# ============================================================
# 3. LOAD DATA
# ============================================================

print("=" * 70)
print("CLASSICAL VS QUANTUM-INSPIRED COMPARISON")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset:", DATA_FILE)
print("Shape:", data.shape)


# ============================================================
# 4. ALL FEATURES
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
# 5. QUANTUM-INSPIRED SELECTED FEATURES
# ============================================================
#
# These are the 7 features selected by our fair
# quantum-inspired probability-vector optimizer.
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
# 6. CLASSICAL BASELINE
# ============================================================
#
# To keep the comparison simple and reproducible, the
# classical baseline uses the first 7 features from the
# original feature set.
#
# Later we can replace this with a formal classical
# feature-selection algorithm if required.
# ============================================================

CLASSICAL_FEATURES = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour",
    "signature_size"
]


# ============================================================
# 7. CHECK COLUMNS
# ============================================================

required_columns = list(
    set(
        ALL_FEATURES
        + QI_FEATURES
        + CLASSICAL_FEATURES
        + [TARGET]
    )
)


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


X = data[ALL_FEATURES].copy()

y = data[TARGET].copy()


# ============================================================
# 8. SAME DATA SPLIT FOR EVERY METHOD
# ============================================================
#
# 60% training
# 20% validation
# 20% final test
#
# The test set is untouched until the final evaluation.
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


# ============================================================
# 9. MODEL CREATOR
# ============================================================

def create_model(selected_features):

    categorical_features = []
    numeric_features = []

    for feature in selected_features:

        if feature == "algorithm":

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


    return pipeline


# ============================================================
# 10. EVALUATION FUNCTION
# ============================================================

def evaluate_method(name, selected_features):

    print("\n")
    print("=" * 70)
    print(name)
    print("=" * 70)

    print("\nFeatures used:")

    for feature in selected_features:

        print(" -", feature)


    model = create_model(
        selected_features
    )


    # --------------------------------------------------------
    # Train using training + validation data
    # --------------------------------------------------------

    X_train_final = pd.concat(
        [
            X_train[selected_features],
            X_validation[selected_features]
        ]
    )


    y_train_final = pd.concat(
        [
            y_train,
            y_validation
        ]
    )


    print("\nTraining model...")


    model.fit(
        X_train_final,
        y_train_final
    )


    # --------------------------------------------------------
    # Final test
    # --------------------------------------------------------

    predictions = model.predict(
        X_test[selected_features]
    )


    probabilities = model.predict_proba(
        X_test[selected_features]
    )[:, 1]


    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

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


    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions
    ).ravel()


    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0
    )


    false_negative_rate = (
        fn / (fn + tp)
        if (fn + tp) > 0
        else 0
    )


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\nFinal test results:")

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

    print(
        "FPR      :",
        round(false_positive_rate, 4)
    )

    print(
        "FNR      :",
        round(false_negative_rate, 4)
    )


    print("\nConfusion Matrix:")

    print(
        f"TN={tn}  FP={fp}"
    )

    print(
        f"FN={fn}  TP={tp}"
    )


    return {

        "method": name,

        "feature_count":
            len(selected_features),

        "selected_features":
            ", ".join(selected_features),

        "accuracy":
            accuracy,

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "roc_auc":
            roc_auc,

        "false_positive_rate":
            false_positive_rate,

        "false_negative_rate":
            false_negative_rate,

        "true_negative":
            tn,

        "false_positive":
            fp,

        "false_negative":
            fn,

        "true_positive":
            tp

    }


# ============================================================
# 11. RUN COMPARISONS
# ============================================================

results = []


# ------------------------------------------------------------
# A. ALL FEATURES
# ------------------------------------------------------------

results.append(
    evaluate_method(
        "All 15 Features",
        ALL_FEATURES
    )
)


# ------------------------------------------------------------
# B. CLASSICAL BASELINE
# ------------------------------------------------------------

results.append(
    evaluate_method(
        "Classical 7-Feature Baseline",
        CLASSICAL_FEATURES
    )
)


# ------------------------------------------------------------
# C. QUANTUM-INSPIRED
# ------------------------------------------------------------

results.append(
    evaluate_method(
        "Quantum-Inspired 7-Feature Selection",
        QI_FEATURES
    )
)


# ============================================================
# 12. COMPARISON TABLE
# ============================================================

results_df = pd.DataFrame(
    results
)


print("\n")
print("=" * 70)
print("FINAL COMPARISON")
print("=" * 70)


print(
    results_df[
        [
            "method",
            "feature_count",
            "accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "false_positive_rate",
            "false_negative_rate"
        ]
    ].to_string(index=False)
)


# ============================================================
# 13. SAVE RESULTS
# ============================================================

results_df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n")
print("=" * 70)
print("COMPARISON COMPLETE")
print("=" * 70)


print("\nResults saved to:")

print(OUTPUT_FILE)