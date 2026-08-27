from pathlib import Path

import pandas as pd

from risk_scoring import calculate_risk


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_v3_extended.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "risk_scored_events.csv"
)


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 70)
print("DAY 4 - SECURITY EVENT RISK ANALYSIS")
print("=" * 70)

data = pd.read_csv(DATA_FILE)

print("\nDataset loaded.")
print("Records:", len(data))


# ============================================================
# CALCULATE RISK
# ============================================================

risk_scores = []

threat_levels = []

risk_reasons = []


for _, row in data.iterrows():

    event = {

        "verification_result":
            row["verification_result"],

        "verification_frequency":
            row["verification_frequency"],

        "certificate_valid":
            row["certificate_valid"],

        "source_frequency":
            row["source_frequency"],

        "failed_verification_rate":
            row["failed_verification_rate"],

        "metadata_anomaly":
            row["metadata_anomaly"],

        "replay_indicator":
            row["replay_indicator"]
    }


    result = calculate_risk(event)


    risk_scores.append(
        result.score
    )

    threat_levels.append(
        result.level
    )

    risk_reasons.append(
        "; ".join(result.reasons)
        if result.reasons
        else "No significant risk indicators"
    )


# ============================================================
# ADD RESULTS
# ============================================================

data["risk_score"] = risk_scores

data["threat_level"] = threat_levels

data["risk_reasons"] = risk_reasons


# ============================================================
# SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("RISK ANALYSIS SUMMARY")
print("=" * 70)


print("\nThreat level distribution:")

print(
    data["threat_level"]
    .value_counts()
)


print("\nAverage risk score:")

print(
    round(
        data["risk_score"].mean(),
        2
    )
)


print("\nMinimum risk score:")

print(
    data["risk_score"].min()
)


print("\nMaximum risk score:")

print(
    data["risk_score"].max()
)


# ============================================================
# TOP 10 HIGHEST-RISK EVENTS
# ============================================================

print("\n")
print("=" * 70)
print("TOP 10 HIGHEST-RISK EVENTS")
print("=" * 70)


top_events = data.sort_values(
    by="risk_score",
    ascending=False
).head(10)


display_columns = [

    "verification_result",

    "failed_verification_rate",

    "certificate_valid",

    "source_frequency",

    "metadata_anomaly",

    "replay_indicator",

    "risk_score",

    "threat_level"

]


print(
    top_events[
        display_columns
    ].to_string(index=False)
)


# ============================================================
# SAVE
# ============================================================

data.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n")
print("=" * 70)

print("RISK ANALYSIS COMPLETE")

print("=" * 70)

print("\nSaved to:")

print(
    OUTPUT_FILE
)