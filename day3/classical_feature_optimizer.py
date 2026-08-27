from pathlib import Path
from time import perf_counter

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)


# ==================================================
# PATHS
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

RESULT_FILE = (
    PROJECT_ROOT
    / "data"
    / "classical_optimization_day3.csv"
)


# ==================================================
# LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)

print("Dataset loaded.")
print("Records:", len(data))


# ==================================================
# FEATURES
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


# ==================================================
# EVALUATION FUNCTION
# ==================================================

def evaluate(selected_features):

    categorical_features = []

    numeric_features = []

    for feature in selected_features:

        if feature == "algorithm":
            categorical_features.append(feature)

        else:
            numeric_features.append(feature)


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


    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )


    pipeline = Pipeline(
        steps=[
            (
                "preprocessing",
                preprocessor
            ),
            (
                "model",
                model
            )
        ]
    )


    pipeline.fit(
        X_train[selected_features],
        y_train
    )


    predictions = pipeline.predict(
        X_test[selected_features]
    )


    probabilities = pipeline.predict_proba(
        X_test[selected_features]
    )[:, 1]


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


    # Feature-count penalty
    score = (
        f1
        - 0.01 * len(selected_features)
    )


    return {
        "features": tuple(selected_features),
        "feature_count": len(selected_features),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "score": score
    }


# ==================================================
# GREEDY FORWARD SELECTION
# ==================================================

start_time = perf_counter()

selected = []

remaining = features.copy()

results = []

iteration = 0


print("\n")
print("=" * 70)
print("CLASSICAL GREEDY FEATURE OPTIMIZATION")
print("=" * 70)


while remaining:

    iteration += 1

    candidates = []


    for feature in remaining:

        candidate_features = (
            selected
            + [feature]
        )


        result = evaluate(
            candidate_features
        )


        candidates.append(
            result
        )


    best_candidate = max(
        candidates,
        key=lambda x: x["score"]
    )


    selected = list(
        best_candidate["features"]
    )


    remaining.remove(
        selected[-1]
    )


    results.append(
        best_candidate
    )


    print(
        f"\nStep {iteration}"
    )

    print(
        "Selected:",
        selected
    )

    print(
        f"F1: {best_candidate['f1']:.4f}"
    )

    print(
        f"Score: {best_candidate['score']:.4f}"
    )


    # Stop when adding another feature
    # no longer improves the score.

    if iteration > 1:

        previous_score = (
            results[-2]["score"]
        )

        current_score = (
            results[-1]["score"]
        )

        if current_score < previous_score:

            print(
                "\nNo further improvement."
            )

            # Remove the last feature
            selected.pop()

            results.pop()

            break


# ==================================================
# TIME
# ==================================================

execution_time = (
    perf_counter()
    - start_time
)


# ==================================================
# BEST RESULT
# ==================================================

best_result = max(
    results,
    key=lambda x: x["score"]
)


print("\n")
print("=" * 70)
print("BEST CLASSICAL SOLUTION")
print("=" * 70)


print("\nSelected features:")

for feature in best_result["features"]:

    print(
        " -",
        feature
    )


print(
    "\nFeature count:",
    best_result["feature_count"]
)

print(
    "Precision:",
    round(
        best_result["precision"],
        4
    )
)

print(
    "Recall:",
    round(
        best_result["recall"],
        4
    )
)

print(
    "F1:",
    round(
        best_result["f1"],
        4
    )
)

print(
    "ROC-AUC:",
    round(
        best_result["roc_auc"],
        4
    )
)

print(
    "Optimization score:",
    round(
        best_result["score"],
        4
    )
)

print(
    "Execution time:",
    round(
        execution_time,
        2
    ),
    "seconds"
)


# ==================================================
# SAVE RESULTS
# ==================================================

result_rows = []

for result in results:

    row = result.copy()

    row["features"] = ", ".join(
        result["features"]
    )

    row["execution_time"] = (
        execution_time
    )

    result_rows.append(
        row
    )


results_df = pd.DataFrame(
    result_rows
)


results_df.to_csv(
    RESULT_FILE,
    index=False
)


print("\nResults saved to:")

print(
    RESULT_FILE
)