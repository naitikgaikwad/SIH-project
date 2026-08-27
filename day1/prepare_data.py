import pandas as pd


# Load dataset
data = pd.read_csv("../data/security_events.csv")


# Separate features and target
X = data.drop("threat", axis=1)
y = data["threat"]


# Remove source_id because it is an identifier,
# not a meaningful numerical measurement.
X = X.drop("source_id", axis=1)


print("Features:")
print(X.head())

print("\nTarget:")
print(y.head())

print("\nFeature columns:")
print(X.columns.tolist())

print("\nTarget distribution:")
print(y.value_counts())