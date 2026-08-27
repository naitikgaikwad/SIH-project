from pathlib import Path
from itertools import combinations

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
# 1. PROJECT PATHS
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = PROJECT_ROOT / "data" / "security_events_v3.csv"


# ==================================================
# 2. LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)

print("Dataset loaded.")
print("Records:", len(data))


# ==================================================
# 3. FEATURES AND TARGET
# ==================================================

target = "threat"

features = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour"
]

X = data[features]

y = data[target]


# ==================================================
# 4. TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==================================================
# 5. FUNCTION TO EVALUATE A FEATURE SUBSET
# ==================================================

def evaluate_features(selected_features):

    X_train_subset = X_train[list(selected_features)]

    X_test_subset = X_test[list(selected_features)]

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
                OneHotEncoder(handle_unknown="ignore"),
                categorical_features
            ),
            (
                "numeric",
                "passthrough",
                numeric_features
            )
        ],
        remainder="drop"
    )


    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight="balanced"
    )


    pipeline = Pipeline(
        steps=[
            ("preprocessing", preprocessor),
            ("model", model)
        ]
    )


    pipeline.fit(
        X_train_subset,
        y_train
    )


    predictions = pipeline.predict(
        X_test_subset
    )

    probabilities = pipeline.predict_proba(
        X_test_subset
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


    return precision, recall, f1, roc_auc


# ==================================================
# 6. EXHAUSTIVE FEATURE SEARCH
# ==================================================

results = []

total_subsets = 0


for size in range(1, len(features) + 1):

    for subset in combinations(features, size):

        total_subsets += 1

        precision, recall, f1, roc_auc = evaluate_features(
            subset
        )


        results.append({
            "feature_count": size,
            "features": ", ".join(subset),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": roc_auc
        })


# ==================================================
# 7. RESULTS DATAFRAME
# ==================================================

results_df = pd.DataFrame(results)


# ==================================================
# 8. BEST SUBSETS
# ==================================================

results_df = results_df.sort_values(
    by=["f1", "roc_auc"],
    ascending=False
)


print("\n")
print("=" * 70)
print("CLASSICAL FEATURE SELECTION BENCHMARK")
print("=" * 70)

print("\nTotal subsets evaluated:", total_subsets)


print("\nTop 10 feature subsets:")

print(
    results_df.head(10).to_string(index=False)
)


# ==================================================
# 9. BEST COMPACT SUBSET
# ==================================================

# Give priority to fewer features when F1 is very close.
best_f1 = results_df["f1"].max()

close_results = results_df[
    results_df["f1"] >= best_f1 - 0.02
]

best_compact = close_results.sort_values(
    by=["feature_count", "f1", "roc_auc"],
    ascending=[True, False, False]
).iloc[0]


print("\n")
print("=" * 70)
print("BEST COMPACT FEATURE SUBSET")
print("=" * 70)

print(
    "\nFeatures:",
    best_compact["features"]
)

print(
    "Feature count:",
    int(best_compact["feature_count"])
)

print(
    "Precision:",
    round(best_compact["precision"], 4)
)

print(
    "Recall:",
    round(best_compact["recall"], 4)
)

print(
    "F1:",
    round(best_compact["f1"], 4)
)

print(
    "ROC-AUC:",
    round(best_compact["roc_auc"], 4)
)


# ==================================================
# 10. SAVE RESULTS
# ==================================================

output_file = (
    PROJECT_ROOT
    / "data"
    / "feature_selection_results.csv"
)

results_df.to_csv(
    output_file,
    index=False
)


print("\nResults saved to:")
print(output_file)