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
    confusion_matrix,
    classification_report
)


# ------------------------------------------------
# 1. Load dataset
# ------------------------------------------------

data = pd.read_csv("../data/security_events.csv")


# ------------------------------------------------
# 2. Separate features and target
# ------------------------------------------------

X = data.drop("threat", axis=1)
y = data["threat"]


# Remove source_id
X = X.drop("source_id", axis=1)


# ------------------------------------------------
# 3. Identify categorical columns
# ------------------------------------------------

categorical_features = ["algorithm"]

numeric_features = [
    "verification_result",
    "failed_attempts",
    "verification_frequency",
    "key_size",
    "hour"
]


# ------------------------------------------------
# 4. Preprocessing
# ------------------------------------------------

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


# ------------------------------------------------
# 5. Create Random Forest
# ------------------------------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)


# ------------------------------------------------
# 6. Create complete pipeline
# ------------------------------------------------

pipeline = Pipeline(
    steps=[
        ("preprocessing", preprocessor),
        ("model", model)
    ]
)


# ------------------------------------------------
# 7. Train/Test split
# ------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# ------------------------------------------------
# 8. Train model
# ------------------------------------------------

pipeline.fit(X_train, y_train)

print("\nModel training completed.")


# ------------------------------------------------
# 9. Make predictions
# ------------------------------------------------

y_pred = pipeline.predict(X_test)


# ------------------------------------------------
# 10. Evaluation
# ------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(y_test, y_pred)

recall = recall_score(y_test, y_pred)

f1 = f1_score(y_test, y_pred)

cm = confusion_matrix(y_test, y_pred)


print("\n--- MODEL PERFORMANCE ---")

print("Accuracy :", accuracy)
print("Precision:", precision)
print("Recall   :", recall)
print("F1 Score :", f1)

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))