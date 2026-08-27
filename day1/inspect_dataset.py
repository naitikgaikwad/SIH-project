import pandas as pd


# Load dataset
data = pd.read_csv("../data/security_events.csv")


# Display first 5 rows
print("\nFirst 5 rows:")
print(data.head())


# Dataset dimensions
print("\nDataset shape:")
print(data.shape)


# Column information
print("\nDataset information:")
print(data.info())


# Check missing values
print("\nMissing values:")
print(data.isnull().sum())


# Check class distribution
print("\nThreat distribution:")
print(data["threat"].value_counts())