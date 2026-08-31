from pathlib import Path
import random

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


# ============================================================
# 1. PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# IMPORTANT:
# Use the extended dataset, NOT security_events_v3.csv
DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

OUTPUT_FILE = (
    Path(__file__).resolve().parent
    / "day7_fair_comparison_v2.csv"
)


# ============================================================
# 2. RANDOM SEED
# ============================================================

RANDOM_SEED = 42

random.seed(RANDOM_SEED)


# ============================================================
# 3. LOAD DATASET
# ============================================================

print("=" * 70)
print("DAY 7 - FAIR QUANTUM-INSPIRED FEATURE SELECTION EVALUATION")
print("=" * 70)

print("\nLoading dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset:", DATA_FILE)
print("Shape:", data.shape)


# ============================================================
# 4. FEATURES
# ============================================================

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

TARGET = "threat"


# ============================================================
# 5. CHECK REQUIRED COLUMNS
# ============================================================

missing_columns = [
    column
    for column in features + [TARGET]
    if column not in data.columns
]

if missing_columns:

    print("\nERROR: Missing columns:")

    for column in missing_columns:
        print(" -", column)

    raise SystemExit(1)


X = data[features].copy()
y = data[TARGET].copy()


print("\nNumber of features:", len(features))

print("\nThreat distribution:")
print(y.value_counts())


# ============================================================
# 6. TRAIN / VALIDATION / TEST SPLIT
# ============================================================
#
# 60% Training
# 20% Validation
# 20% Final Test
#
# The final test set is NEVER used during feature selection.
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
# 7. CREATE MODEL FOR FEATURE SUBSET
# ============================================================

def create_subset_model(selected_features):

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
# 8. VALIDATION EVALUATION
# ============================================================

LAMBDA = 0.01


def evaluate_validation(selected_features):

    if not selected_features:
        return None


    model = create_subset_model(
        selected_features
    )


    model.fit(
        X_train[selected_features],
        y_train
    )


    predictions = model.predict(
        X_validation[selected_features]
    )


    probabilities = model.predict_proba(
        X_validation[selected_features]
    )[:, 1]


    precision = precision_score(
        y_validation,
        predictions,
        zero_division=0
    )


    recall = recall_score(
        y_validation,
        predictions,
        zero_division=0
    )


    f1 = f1_score(
        y_validation,
        predictions,
        zero_division=0
    )


    roc_auc = roc_auc_score(
        y_validation,
        probabilities
    )


    # Objective:
    #
    # High F1 = better detection
    # Small feature penalty = encourages compact feature sets

    score = (
        f1
        -
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


# ============================================================
# 9. QUANTUM-INSPIRED PROBABILITY VECTOR
# ============================================================
#
# Each feature starts with a 0.5 probability of selection.
#
# The optimizer repeatedly samples feature subsets.
# Good subsets increase their selection probabilities.
#
# This is a CLASSICAL algorithm inspired by
# probability-based state representation.
#
# It is NOT quantum computing.
# ============================================================

probabilities = {
    feature: 0.5
    for feature in features
}


# ============================================================
# 10. OPTIMIZATION PARAMETERS
# ============================================================

NUM_ITERATIONS = 30

SOLUTIONS_PER_ITERATION = 10

LEARNING_RATE = 0.20


# ============================================================
# 11. QUANTUM-INSPIRED OPTIMIZATION
# ============================================================

print("\n")
print("=" * 70)
print("QUANTUM-INSPIRED FEATURE SELECTION")
print("=" * 70)


best_solution = None


for iteration in range(NUM_ITERATIONS):

    iteration_solutions = []


    # --------------------------------------------------------
    # Generate candidate feature subsets
    # --------------------------------------------------------

    for _ in range(SOLUTIONS_PER_ITERATION):

        selected_features = []


        for feature in features:

            if random.random() < probabilities[feature]:

                selected_features.append(
                    feature
                )


        # Prevent empty solution

        if not selected_features:

            selected_features.append(
                random.choice(features)
            )


        result = evaluate_validation(
            selected_features
        )


        iteration_solutions.append(result)


    # --------------------------------------------------------
    # Best candidate from this iteration
    # --------------------------------------------------------

    iteration_best = max(
        iteration_solutions,
        key=lambda x: x["score"]
    )


    # --------------------------------------------------------
    # Global best
    # --------------------------------------------------------

    if (
        best_solution is None
        or iteration_best["score"]
        > best_solution["score"]
    ):

        best_solution = iteration_best.copy()


    # --------------------------------------------------------
    # Probability update
    # --------------------------------------------------------

    selected = set(
        iteration_best["features"]
    )


    for feature in features:

        if feature in selected:

            probabilities[feature] += (
                LEARNING_RATE
                *
                (
                    1
                    -
                    probabilities[feature]
                )
            )

        else:

            probabilities[feature] -= (
                LEARNING_RATE
                *
                probabilities[feature]
            )


    # --------------------------------------------------------
    # Progress
    # --------------------------------------------------------

    print(
        f"Iteration {iteration + 1:02d}"
        f" | Validation F1: "
        f"{iteration_best['f1']:.4f}"
        f" | Score: "
        f"{iteration_best['score']:.4f}"
        f" | Features: "
        f"{len(iteration_best['features'])}"
    )


# ============================================================
# 12. SELECTED FEATURES
# ============================================================

selected_features = best_solution["features"]


print("\n")
print("=" * 70)
print("SELECTED FEATURE SUBSET")
print("=" * 70)


for feature in selected_features:

    print(" -", feature)


print(
    "\nSelected feature count:",
    len(selected_features)
)


# ============================================================
# 13. FINAL MODEL
# ============================================================
#
# The training + validation data is combined.
#
# The final test set remains untouched until evaluation.
# ============================================================

print("\nTraining final model...")


final_model = create_subset_model(
    selected_features
)


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


final_model.fit(
    X_train_final,
    y_train_final
)


# ============================================================
# 14. FINAL TEST
# ============================================================

test_predictions = final_model.predict(
    X_test[selected_features]
)


test_probabilities = final_model.predict_proba(
    X_test[selected_features]
)[:, 1]


final_accuracy = accuracy_score(
    y_test,
    test_predictions
)


final_precision = precision_score(
    y_test,
    test_predictions,
    zero_division=0
)


final_recall = recall_score(
    y_test,
    test_predictions,
    zero_division=0
)


final_f1 = f1_score(
    y_test,
    test_predictions,
    zero_division=0
)


final_roc_auc = roc_auc_score(
    y_test,
    test_probabilities
)


# ============================================================
# 15. FINAL RESULTS
# ============================================================

print("\n")
print("=" * 70)
print("FINAL UNTOUCHED TEST RESULTS")
print("=" * 70)


print(
    "Accuracy :",
    round(final_accuracy, 4)
)


print(
    "Precision:",
    round(final_precision, 4)
)


print(
    "Recall   :",
    round(final_recall, 4)
)


print(
    "F1       :",
    round(final_f1, 4)
)


print(
    "ROC-AUC  :",
    round(final_roc_auc, 4)
)


# ============================================================
# 16. FINAL FEATURE PROBABILITIES
# ============================================================

print("\n")
print("=" * 70)
print("FINAL FEATURE SELECTION PROBABILITIES")
print("=" * 70)


for feature in features:

    print(
        f"{feature:30s}"
        f" {probabilities[feature]:.4f}"
    )


# ============================================================
# 17. SAVE RESULTS
# ============================================================

result_row = {

    "method":
        "Quantum-Inspired Probability-Vector Feature Selection",

    "feature_count":
        len(selected_features),

    "selected_features":
        ", ".join(selected_features),

    "accuracy":
        final_accuracy,

    "precision":
        final_precision,

    "recall":
        final_recall,

    "f1":
        final_f1,

    "roc_auc":
        final_roc_auc,

    "random_seed":
        RANDOM_SEED,

    "test_size":
        0.20,

    "optimization_iterations":
        NUM_ITERATIONS,

    "solutions_per_iteration":
        SOLUTIONS_PER_ITERATION
}


result_df = pd.DataFrame(
    [result_row]
)


result_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# 18. COMPLETION
# ============================================================

print("\n")
print("=" * 70)
print("EVALUATION COMPLETE")
print("=" * 70)


print("\nResults saved to:")

print(OUTPUT_FILE)