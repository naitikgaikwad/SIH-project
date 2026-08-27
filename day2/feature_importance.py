from pathlib import Path

import pandas as pd
import joblib


# ==========================================
# PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = PROJECT_ROOT / "models" / "random_forest_baseline.pkl"


# ==========================================
# LOAD MODEL
# ==========================================

pipeline = joblib.load(MODEL_FILE)


# ==========================================
# GET MODEL COMPONENTS
# ==========================================

model = pipeline.named_steps["model"]

preprocessor = pipeline.named_steps["preprocessing"]


# ==========================================
# GET FEATURE NAMES
# ==========================================

feature_names = preprocessor.get_feature_names_out()


# ==========================================
# GET FEATURE IMPORTANCE
# ==========================================

importances = model.feature_importances_


importance_data = pd.DataFrame({
    "feature": feature_names,
    "importance": importances
})


importance_data = importance_data.sort_values(
    "importance",
    ascending=False
)


# ==========================================
# DISPLAY
# ==========================================

print("\n========================================")
print("FEATURE IMPORTANCE")
print("========================================")

print(
    importance_data.to_string(index=False)
)


print("\n========================================")
print("MOST IMPORTANT FEATURE")
print("========================================")

top_feature = importance_data.iloc[0]

print(
    f"{top_feature['feature']} "
    f"-> {top_feature['importance']:.4f}"
)