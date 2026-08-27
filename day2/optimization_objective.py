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
# PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = PROJECT_ROOT / "data" / "security_events_v3.csv"


# ==================================================
# LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)


# ==================================================
# FEATURES
# ==================================================

features = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "algorithm",
    "hour"
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
# PENALTY
# ==================================================

LAMBDA = 0.01


# ==================================================
# EVALUATE FEATURE SUBSET
# ==================================================

def evaluate_subset(selected_features):

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
        ]
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


    feature_count = len(selected_features)


    # ------------------------------------------
    # OPTIMIZATION OBJECTIVE
    # ------------------------------------------

    score = f1 - (
        LAMBDA * feature_count
    )


    return {
        "features": selected_features,
        "feature_count": feature_count,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "score": score
    }


# ==================================================
# EXHAUSTIVE SEARCH
# ==================================================

results = []


for size in range(
    1,
    len(features) + 1
):

    for subset in combinations(
        features,
        size
    ):

        result = evaluate_subset(
            subset
        )

        results.append(
            result
        )


# ==================================================
# DATAFRAME
# ==================================================

results_df = pd.DataFrame(results)


# ==================================================
# SORT BY OBJECTIVE
# ==================================================

results_df = results_df.sort_values(
    by="score",
    ascending=False
)


# ==================================================
# DISPLAY
# ==================================================

print("\n")
print("=" * 70)
print("CLASSICAL OPTIMIZATION BENCHMARK")
print("=" * 70)


print(
    "\nLambda:",
    LAMBDA
)


print(
    "\nTotal solutions evaluated:",
    len(results_df)
)


print(
    "\nTop 10 solutions:"
)


display_columns = [
    "feature_count",
    "features",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "score"
]


print(
    results_df[
        display_columns
    ].head(10).to_string(
        index=False
    )
)


# ==================================================
# BEST SOLUTION
# ==================================================

best = results_df.iloc[0]


print("\n")
print("=" * 70)
print("BEST OPTIMIZATION SOLUTION")
print("=" * 70)


print(
    "\nSelected features:"
)

for feature in best["features"]:

    print(
        " -",
        feature
    )


print(
    "\nFeature count:",
    int(best["feature_count"])
)

print(
    "Precision:",
    round(best["precision"], 4)
)

print(
    "Recall:",
    round(best["recall"], 4)
)

print(
    "F1:",
    round(best["f1"], 4)
)

print(
    "ROC-AUC:",
    round(best["roc_auc"], 4)
)

print(
    "Optimization score:",
    round(best["score"], 4)
)