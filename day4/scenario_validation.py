import os
import joblib
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_FILE = os.path.join(
    PROJECT_ROOT,
    "models",
    "random_forest_day3.pkl"
)

DATA_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "security_events_v3_extended.csv"
)

OUTPUT_FILE = os.path.join(
    PROJECT_ROOT,
    "data",
    "controlled_scenario_results.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

FEATURE_COLUMNS = [
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


# ============================================================
# HEADER
# ============================================================

print("=" * 70)
print("DAY 5.5 - CONTROLLED SECURITY SCENARIO VALIDATION")
print("=" * 70)


# ============================================================
# CHECK FILES
# ============================================================

if not os.path.exists(MODEL_FILE):
    print("\nERROR: Model not found:")
    print(MODEL_FILE)
    raise SystemExit

if not os.path.exists(DATA_FILE):
    print("\nERROR: Dataset not found:")
    print(DATA_FILE)
    raise SystemExit


# ============================================================
# LOAD
# ============================================================

model = joblib.load(MODEL_FILE)
data = pd.read_csv(DATA_FILE)

print("\nModel loaded successfully.")
print("Dataset records:", len(data))


# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk(event):

    score = 0
    reasons = []

    # Signature verification
    if event["verification_result"] == 0:
        score += 25
        reasons.append(
            "Digital signature verification failed"
        )

    # Certificate
    if event["certificate_valid"] == 0:
        score += 15
        reasons.append(
            "Certificate validation failed"
        )

    # Failure rate
    if event["failed_verification_rate"] >= 0.75:
        score += 20
        reasons.append(
            "Very high signature verification failure rate"
        )

    elif event["failed_verification_rate"] >= 0.50:
        score += 10
        reasons.append(
            "High signature verification failure rate"
        )

    # Replay
    if event["replay_indicator"] == 1:
        score += 15
        reasons.append(
            "Possible replay activity detected"
        )

    # Metadata
    if event["metadata_anomaly"] == 1:
        score += 10
        reasons.append(
            "Suspicious document metadata detected"
        )

    # Source frequency
    if event["source_frequency"] >= 40:
        score += 10
        reasons.append(
            "Unusually high verification activity from source"
        )

    elif event["source_frequency"] >= 30:
        score += 5
        reasons.append(
            "Elevated verification activity from source"
        )

    # Verification frequency
    if event["verification_frequency"] >= 30:
        score += 5
        reasons.append(
            "Unusually high verification frequency"
        )

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    return score, level, reasons


# ============================================================
# ML PREDICTION
# ============================================================

def predict_event(event):

    event_df = pd.DataFrame(
        [event[FEATURE_COLUMNS].to_dict()]
    )

    prediction = model.predict(event_df)[0]

    probabilities = model.predict_proba(event_df)[0]

    threat_probability = 0.0

    for class_value, probability in zip(
        model.classes_,
        probabilities
    ):
        if class_value == 1:
            threat_probability = probability

    prediction_name = (
        "THREAT"
        if prediction == 1
        else "NORMAL"
    )

    return prediction_name, threat_probability


# ============================================================
# BASE EVENT
# ============================================================

# Use a normal-looking row only as a source for
# non-security-specific fields.

base = data.iloc[0].copy()


# ============================================================
# FUNCTION TO CREATE CONTROLLED EVENT
# ============================================================

def create_base_event():

    event = base.copy()

    # Neutral security values
    event["verification_result"] = 1
    event["failed_attempts"] = 0
    event["verification_frequency"] = 5
    event["certificate_valid"] = 1
    event["source_frequency"] = 10
    event["failed_verification_rate"] = 0.0
    event["metadata_anomaly"] = 0
    event["replay_indicator"] = 0
    event["time_since_previous"] = 500

    return event


# ============================================================
# CONTROLLED SCENARIOS
# ============================================================

scenarios = []


# ------------------------------------------------------------
# 1. NORMAL
# ------------------------------------------------------------

event = create_base_event()

scenarios.append({
    "name": "NORMAL EVENT",
    "category": "BENIGN",
    "evidence": "No abnormal security indicators",
    "event": event
})


# ------------------------------------------------------------
# 2. DOCUMENT TAMPERING
# ------------------------------------------------------------

event = create_base_event()

event["verification_result"] = 0
event["failed_attempts"] = 4
event["failed_verification_rate"] = 0.8

scenarios.append({
    "name": "DOCUMENT TAMPERING",
    "category": "DOCUMENT_TAMPERING",
    "evidence": "Signature verification failure after document modification",
    "event": event
})


# ------------------------------------------------------------
# 3. REPLAY
# ------------------------------------------------------------

event = create_base_event()

# Signature can remain valid during replay-like activity.
event["verification_result"] = 1
event["replay_indicator"] = 1
event["time_since_previous"] = 1
event["verification_frequency"] = 32

scenarios.append({
    "name": "REPLAY-LIKE ACTIVITY",
    "category": "REPLAY",
    "evidence": "Repeated verification activity with replay indicator",
    "event": event
})


# ------------------------------------------------------------
# 4. CERTIFICATE FAILURE
# ------------------------------------------------------------

event = create_base_event()

event["verification_result"] = 0
event["certificate_valid"] = 0
event["failed_attempts"] = 3
event["failed_verification_rate"] = 0.6

scenarios.append({
    "name": "CERTIFICATE PROBLEM",
    "category": "CERTIFICATE_SECURITY",
    "evidence": "Invalid certificate with failed signature verification",
    "event": event
})


# ------------------------------------------------------------
# 5. BEHAVIORAL ANOMALY
# ------------------------------------------------------------

event = create_base_event()

# Keep signature valid.
event["verification_result"] = 1

# Abnormal activity without cryptographic failure.
event["verification_frequency"] = 35
event["source_frequency"] = 45
event["failed_attempts"] = 3
event["failed_verification_rate"] = 0.5

scenarios.append({
    "name": "BEHAVIORAL ANOMALY",
    "category": "BEHAVIORAL_ANOMALY",
    "evidence": "Unusually high verification activity and elevated failure rate",
    "event": event
})


# ------------------------------------------------------------
# 6. MULTIPLE INDICATORS
# ------------------------------------------------------------

event = create_base_event()

event["verification_result"] = 0
event["certificate_valid"] = 0
event["failed_attempts"] = 10
event["verification_frequency"] = 35
event["failed_verification_rate"] = 1.0
event["source_frequency"] = 50
event["metadata_anomaly"] = 1
event["replay_indicator"] = 1
event["time_since_previous"] = 1

scenarios.append({
    "name": "MULTIPLE SUSPICIOUS INDICATORS",
    "category": "COMBINED_THREAT",
    "evidence": "Multiple independent security indicators",
    "event": event
})


# ============================================================
# RUN SCENARIOS
# ============================================================

results = []


for scenario in scenarios:

    name = scenario["name"]
    category = scenario["category"]
    evidence = scenario["evidence"]
    event = scenario["event"]

    prediction, probability = predict_event(event)

    risk_score, threat_level, reasons = calculate_risk(
        event
    )

    # --------------------------------------------------------
    # Final decision
    # --------------------------------------------------------

    if threat_level == "HIGH":
        assessment = "HIGH-RISK SECURITY EVENT"

    elif threat_level == "MEDIUM":
        assessment = "SUSPICIOUS SECURITY EVENT"

    elif prediction == "THREAT":
        assessment = "SUSPICIOUS SECURITY EVENT"

    else:
        assessment = "NORMAL SECURITY EVENT"


    # --------------------------------------------------------
    # Display
    # --------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("SCENARIO:", name)
    print("=" * 70)

    print("\nAttack Category :", category)

    print(
        "Primary Evidence:",
        evidence
    )

    print(
        "\nSignature Verification :",
        "VALID"
        if event["verification_result"] == 1
        else "INVALID"
    )

    print(
        "ML Prediction          :",
        prediction
    )

    print(
        "ML Threat Probability  :",
        f"{probability * 100:.2f}%"
    )

    print(
        "Risk Score             :",
        f"{risk_score} / 100"
    )

    print(
        "Threat Level           :",
        threat_level
    )

    print("\nContributing Indicators:")

    if reasons:

        for reason in reasons:
            print(" -", reason)

    else:

        print(" - None")

    print(
        "\nFinal Assessment       :",
        assessment
    )


    # --------------------------------------------------------
    # Save result
    # --------------------------------------------------------

    results.append({
        "scenario": name,
        "attack_category": category,
        "primary_evidence": evidence,
        "signature_verification": (
            "VALID"
            if event["verification_result"] == 1
            else "INVALID"
        ),
        "ml_prediction": prediction,
        "ml_probability": round(
            probability,
            4
        ),
        "risk_score": risk_score,
        "threat_level": threat_level,
        "assessment": assessment
    })


# ============================================================
# SAVE RESULTS
# ============================================================

results_df = pd.DataFrame(results)

results_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("CONTROLLED SCENARIO SUMMARY")
print("=" * 70)

print(
    results_df[
        [
            "scenario",
            "attack_category",
            "signature_verification",
            "ml_prediction",
            "risk_score",
            "threat_level",
            "assessment"
        ]
    ].to_string(index=False)
)


print("\nResults saved to:")
print(OUTPUT_FILE)

print("\n")
print("=" * 70)
print("DAY 5.5 VALIDATION COMPLETE")
print("=" * 70)