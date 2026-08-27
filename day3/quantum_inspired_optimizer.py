from pathlib import Path
from time import perf_counter

import numpy as np
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
    / "quantum_inspired_optimization_day3.csv"
)


# ==================================================
# SETTINGS
# ==================================================

RANDOM_SEED = 42

np.random.seed(RANDOM_SEED)

LAMBDA = 0.01

ITERATIONS = 30

POPULATION_SIZE = 20


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
    random_state=RANDOM_SEED,
    stratify=y
)


# ==================================================
# EVALUATION
# ==================================================

def evaluate(solution):

    selected_features = [
        feature
        for feature, selected
        in zip(features, solution)
        if selected == 1
    ]


    # Avoid empty solution

    if len(selected_features) == 0:

        return {
            "features": [],
            "feature_count": 0,
            "precision": 0,
            "recall": 0,
            "f1": 0,
            "roc_auc": 0,
            "score": -1
        }


    categorical_features = []

    numeric_features = []


    for feature in selected_features:

        if feature == "algorithm":

            categorical_features.append(
                feature
            )

        else:

            numeric_features.append(
                feature
            )


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

        random_state=RANDOM_SEED,

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


    score = (

        f1
        - LAMBDA * len(selected_features)
    )


    return {

        "features": selected_features,

        "feature_count":
            len(selected_features),

        "precision":
            precision,

        "recall":
            recall,

        "f1":
            f1,

        "roc_auc":
            roc_auc,

        "score":
            score
    }


# ==================================================
# QUANTUM-INSPIRED OPTIMIZATION
# ==================================================

start_time = perf_counter()


print("\n")

print("=" * 70)

print("QUANTUM-INSPIRED FEATURE OPTIMIZATION")

print("=" * 70)


number_of_features = len(features)


# Start with equal probability

probabilities = np.full(

    number_of_features,

    0.5
)


best_solution = None

best_result = None


history = []


# ==================================================
# MAIN LOOP
# ==================================================

for iteration in range(1, ITERATIONS + 1):

    iteration_best = None


    for _ in range(POPULATION_SIZE):

        # Generate binary feature selection

        solution = (

            np.random.random(
                number_of_features
            )

            < probabilities

        ).astype(int)


        result = evaluate(
            solution
        )


        if (
            iteration_best is None
            or result["score"]
            > iteration_best["score"]
        ):

            iteration_best = result


        if (
            best_result is None
            or result["score"]
            > best_result["score"]
        ):

            best_result = result

            best_solution = solution.copy()


    # ==================================================
    # PROBABILITY UPDATE
    # ==================================================

    for index in range(
        number_of_features
    ):

        if best_solution[index] == 1:

            probabilities[index] = (

                probabilities[index]
                + 0.10

                * (
                    1
                    - probabilities[index]
                )

            )

        else:

            probabilities[index] = (

                probabilities[index]
                - 0.10
                * probabilities[index]

            )


    history.append({

        "iteration":
            iteration,

        "f1":
            best_result["f1"],

        "score":
            best_result["score"],

        "feature_count":
            best_result["feature_count"]

    })


    print(

        f"Iteration {iteration:02d} | "

        f"Best F1: "
        f"{best_result['f1']:.4f} | "

        f"Score: "
        f"{best_result['score']:.4f} | "

        f"Features: "
        f"{best_result['features']}"

    )


# ==================================================
# EXECUTION TIME
# ==================================================

execution_time = (

    perf_counter()
    - start_time
)


# ==================================================
# FINAL RESULT
# ==================================================

print("\n")

print("=" * 70)

print("QUANTUM-INSPIRED OPTIMIZATION RESULT")

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
# FINAL PROBABILITIES
# ==================================================

print("\n")

print("=" * 70)

print("FINAL FEATURE SELECTION PROBABILITIES")

print("=" * 70)


for feature, probability in zip(
    features,
    probabilities
):

    print(
        f"{feature:<30} "
        f"{probability:.4f}"
    )


# ==================================================
# SAVE ITERATION HISTORY
# ==================================================

history_df = pd.DataFrame(
    history
)


history_df.to_csv(
    RESULT_FILE,
    index=False
)


print("\nResults saved to:")

print(
    RESULT_FILE
)