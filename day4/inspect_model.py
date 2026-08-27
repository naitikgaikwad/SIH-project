from pathlib import Path
import joblib


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "random_forest_day3.pkl"
)


print("=" * 70)
print("DAY 4 - MODEL INSPECTION")
print("=" * 70)


model = joblib.load(MODEL_FILE)


print("\nModel type:")
print(type(model))


print("\nModel object:")
print(model)


print("\nModel parameters:")

if hasattr(model, "get_params"):
    print(model.get_params())


print("\nModel inspection complete.")