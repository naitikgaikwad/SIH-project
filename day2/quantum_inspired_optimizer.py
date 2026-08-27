from pathlib import Path
import random

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
# 1. PROJECT PATH
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = PROJECT_ROOT / "data" / "security_events_v3.csv"


# ==================================================
# 2. LOAD DATA
# ==================================================

data = pd.read_csv(DATA_FILE)


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
# 3. TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# ==================================================
# 4. OBJECTIVE PARAMETERS
# ==================================================

LAMBDA = 0.01

NUM_ITERATIONS = 30

SOLUTIONS_PER_ITERATION = 10

LEARNING_RATE = 0.20


# ==================================================
# 5. EVALUATION FUNCTION
# ==================================================

def evaluate_solution(selected_features):

    if len(selected_features) == 0:
        return None


    X_train_subset = X_train[selected_features]

    X_test_subset = X_test[selected_features]


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


    score = f1 - (
        LAMBDA * len(selected_features)
    )


    return {
        "features": selected_features,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "score": score
    }


# ==================================================
# 6. QUANTUM-INSPIRED PROBABILITY VECTOR
# ==================================================

probabilities = {
    feature: 0.5
    for feature in features
}


# ==================================================
# 7. BEST SOLUTION
# ==================================================

best_solution = None


# ==================================================
# 8. OPTIMIZATION LOOP
# ==================================================

for iteration in range(
    NUM_ITERATIONS
):

    iteration_solutions = []


    # ----------------------------------------------
    # GENERATE CANDIDATE SOLUTIONS
    # ----------------------------------------------

    for _ in range(
        SOLUTIONS_PER_ITERATION
    ):

        selected_features = []


        for feature in features:

            if random.random() < probabilities[feature]:

                selected_features.append(
                    feature
                )


        # Prevent empty solution

        if not selected_features:

            feature = random.choice(
                features
            )

            selected_features.append(
                feature
            )


        result = evaluate_solution(
            selected_features
        )


        iteration_solutions.append(
            result
        )


    # ----------------------------------------------
    # FIND BEST SOLUTION THIS ITERATION
    # ----------------------------------------------

    iteration_best = max(
        iteration_solutions,
        key=lambda x: x["score"]
    )


    # ----------------------------------------------
    # GLOBAL BEST
    # ----------------------------------------------

    if (
        best_solution is None
        or iteration_best["score"]
        > best_solution["score"]
    ):

        best_solution = iteration_best


    # ----------------------------------------------
    # UPDATE PROBABILITIES
    # ----------------------------------------------

    selected = set(
        iteration_best["features"]
    )


    for feature in features:

        if feature in selected:

            probabilities[feature] += (
                LEARNING_RATE
                * (
                    1
                    - probabilities[feature]
                )
            )

        else:

            probabilities[feature] -= (
                LEARNING_RATE
                * probabilities[feature]
            )


    # ----------------------------------------------
    # DISPLAY PROGRESS
    # ----------------------------------------------

    print(
        f"Iteration {iteration + 1:02d}"
        f" | Best F1: {iteration_best['f1']:.4f}"
        f" | Score: {iteration_best['score']:.4f}"
        f" | Features: "
        f"{iteration_best['features']}"
    )


# ==================================================
# 9. FINAL RESULT
# ==================================================

print("\n")
print("=" * 70)
print("QUANTUM-INSPIRED OPTIMIZATION RESULT")
print("=" * 70)


print("\nSelected features:")

for feature in best_solution["features"]:

    print(
        " -",
        feature
    )


print(
    "\nFeature count:",
    len(best_solution["features"])
)


print(
    "Precision:",
    round(
        best_solution["precision"],
        4
    )
)


print(
    "Recall:",
    round(
        best_solution["recall"],
        4
    )
)


print(
    "F1:",
    round(
        best_solution["f1"],
        4
    )
)


print(
    "ROC-AUC:",
    round(
        best_solution["roc_auc"],
        4
    )
)


print(
    "Optimization score:",
    round(
        best_solution["score"],
        4
    )
)


# ==================================================
# 10. FINAL PROBABILITIES
# ==================================================

print("\n")
print("=" * 70)
print("FINAL FEATURE SELECTION PROBABILITIES")
print("=" * 70)


for feature in features:

    print(
        f"{feature:30s}"
        f" {probabilities[feature]:.4f}"
    )