import os
import time
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)


# ============================================================
# DAY 7 - FINAL FAIR MODEL EVALUATION
# SIH26141
# ============================================================

print("=" * 75)
print("DAY 7 - FINAL FAIR MODEL EVALUATION")
print("=" * 75)


# ============================================================
# 1. LOAD DATASET
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "security_events_v3_extended.csv"
)

print("\nLoading dataset...")
print("File:", DATA_FILE)

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(
        f"\nDataset not found:\n{DATA_FILE}"
    )

data = pd.read_csv(DATA_FILE)

print("Dataset loaded successfully.")
print("Records:", len(data))


# ============================================================
# 2. DEFINE FEATURES AND TARGET
# ============================================================

TARGET = "threat"

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


CLASSICAL_FEATURES = [
    "failed_attempts",
    "verification_result"
]


QUANTUM_INSPIRED_FEATURES = [
    "verification_result",
    "verification_frequency",
    "certificate_valid",
    "source_frequency",
    "failed_verification_rate",
    "metadata_anomaly",
    "replay_indicator"
]


# ============================================================
# 3. VERIFY DATASET
# ============================================================

print("\n" + "=" * 75)
print("DATASET VALIDATION")
print("=" * 75)

missing_features = [
    feature for feature in ALL_FEATURES
    if feature not in data.columns
]

if missing_features:
    raise ValueError(
        f"Missing required features: {missing_features}"
    )

if TARGET not in data.columns:
    raise ValueError("Target column 'threat' not found.")

print("All required features found.")

print("\nTarget distribution:")
print(data[TARGET].value_counts())


# ============================================================
# 4. SAME TRAIN/TEST SPLIT FOR ALL MODELS
# ============================================================

X = data[ALL_FEATURES]
y = data[TARGET]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# 5. MODEL CREATION FUNCTION
# ============================================================

def create_model(features):

    categorical_features = []

    if "algorithm" in features:
        categorical_features.append("algorithm")

    numeric_features = [
        feature
        for feature in features
        if feature not in categorical_features
    ]

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

    preprocessing = ColumnTransformer(
        transformers=transformers
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessing", preprocessing),
            ("model", model)
        ]
    )

    return pipeline


# ============================================================
# 6. EVALUATION FUNCTION
# ============================================================

def evaluate_model(name, features):

    print("\n" + "-" * 75)
    print(name)
    print("-" * 75)

    print("Features:")
    for feature in features:
        print(" -", feature)

    start_time = time.perf_counter()

    model = create_model(features)

    model.fit(
        X_train[features],
        y_train
    )

    predictions = model.predict(
        X_test[features]
    )

    probabilities = model.predict_proba(
        X_test[features]
    )[:, 1]

    execution_time = time.perf_counter() - start_time

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

    false_positive_rate = fp / (fp + tn)

    false_negative_rate = fn / (fn + tp)

    print("\nPerformance:")
    print(f"Accuracy           : {accuracy:.4f}")
    print(f"Precision          : {precision:.4f}")
    print(f"Recall             : {recall:.4f}")
    print(f"F1 Score           : {f1:.4f}")
    print(f"ROC-AUC            : {roc_auc:.4f}")

    print("\nConfusion Matrix:")
    print(f"TN = {tn}, FP = {fp}")
    print(f"FN = {fn}, TP = {tp}")

    print(f"\nFalse Positive Rate : {false_positive_rate:.4f}")
    print(f"False Negative Rate : {false_negative_rate:.4f}")

    print(
        f"Feature count      : {len(features)}"
    )

    print(
        f"Execution time     : {execution_time:.4f} seconds"
    )

    return {
        "approach": name,
        "feature_count": len(features),
        "features": ", ".join(features),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "true_positive": tp,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "execution_time_seconds": execution_time
    }


# ============================================================
# 7. RUN THREE FAIR EXPERIMENTS
# ============================================================

results = []


# ------------------------------------------------------------
# A. ALL FEATURES
# ------------------------------------------------------------

results.append(
    evaluate_model(
        "ALL FEATURES",
        ALL_FEATURES
    )
)


# ------------------------------------------------------------
# B. CLASSICAL FEATURE OPTIMIZATION
# ------------------------------------------------------------

results.append(
    evaluate_model(
        "CLASSICAL OPTIMIZATION",
        CLASSICAL_FEATURES
    )
)


# ------------------------------------------------------------
# C. QUANTUM-INSPIRED FEATURE OPTIMIZATION
# ------------------------------------------------------------

results.append(
    evaluate_model(
        "QUANTUM-INSPIRED OPTIMIZATION",
        QUANTUM_INSPIRED_FEATURES
    )
)


# ============================================================
# 8. FINAL COMPARISON
# ============================================================

results_df = pd.DataFrame(results)

print("\n")
print("=" * 75)
print("FINAL COMPARISON")
print("=" * 75)

comparison_columns = [
    "approach",
    "feature_count",
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "false_positive_rate",
    "false_negative_rate",
    "execution_time_seconds"
]

print(
    results_df[
        comparison_columns
    ].to_string(index=False)
)


# ============================================================
# 9. SAVE RESULTS
# ============================================================

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "day7_final_comparison.csv"
)

results_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nResults saved to:")
print(OUTPUT_FILE)


# ============================================================
# 10. BEST F1 RESULT
# ============================================================

best_f1 = results_df.loc[
    results_df["f1"].idxmax()
]

print("\n" + "=" * 75)
print("BEST F1 RESULT")
print("=" * 75)

print(
    "Approach:",
    best_f1["approach"]
)

print(
    "F1 Score:",
    f"{best_f1['f1']:.4f}"
)

print(
    "Precision:",
    f"{best_f1['precision']:.4f}"
)

print(
    "Recall:",
    f"{best_f1['recall']:.4f}"
)

print(
    "ROC-AUC:",
    f"{best_f1['roc_auc']:.4f}"
)

print(
    "Feature count:",
    int(best_f1["feature_count"])
)


print("\n")
print("=" * 75)
print("DAY 7 FINAL EVALUATION COMPLETE")
print("=" * 75)