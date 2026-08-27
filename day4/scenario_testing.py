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


# ============================================================
# LOAD MODEL AND DATA
# ============================================================

print("=" * 70)
print("DAY 5 - CONTROLLED SECURITY SCENARIO TESTING")
print("=" * 70)

if not os.path.exists(MODEL_FILE):
    print("\nERROR: Model not found:")
    print(MODEL_FILE)
    raise SystemExit

if not os.path.exists(DATA_FILE):
    print("\nERROR: Dataset not found:")
    print(DATA_FILE)
    raise SystemExit


model = joblib.load(MODEL_FILE)
data = pd.read_csv(DATA_FILE)

print("\nModel loaded successfully.")
print("Dataset records:", len(data))


# ============================================================
# FEATURES USED BY MODEL
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
# RISK SCORING
# ============================================================

def calculate_risk(event):

    score = 0
    reasons = []

    # Signature verification failure
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
# SCENARIO CREATION
# ============================================================

# Use one real dataset event as the base.
base_event = data.iloc[0].copy()


scenarios = []


# ------------------------------------------------------------
# Scenario 1: Normal event
# ------------------------------------------------------------

normal = base_event.copy()

normal["verification_result"] = 1
normal["certificate_valid"] = 1
normal["failed_attempts"] = 0
normal["failed_verification_rate"] = 0.0
normal["metadata_anomaly"] = 0
normal["replay_indicator"] = 0
normal["source_frequency"] = 10
normal["verification_frequency"] = 5

scenarios.append(
    ("NORMAL EVENT", normal)
)


# ------------------------------------------------------------
# Scenario 2: Document tampering
# ------------------------------------------------------------

tampering = base_event.copy()

tampering["verification_result"] = 0
tampering["certificate_valid"] = 1
tampering["failed_attempts"] = 4
tampering["failed_verification_rate"] = 0.8

scenarios.append(
    ("DOCUMENT TAMPERING", tampering)
)


# ------------------------------------------------------------
# Scenario 3: Repeated verification failures
# ------------------------------------------------------------

repeated_failures = base_event.copy()

repeated_failures["verification_result"] = 0
repeated_failures["failed_attempts"] = 9
repeated_failures["verification_frequency"] = 32
repeated_failures["failed_verification_rate"] = 0.9

scenarios.append(
    ("REPEATED VERIFICATION FAILURES",
     repeated_failures)
)


# ------------------------------------------------------------
# Scenario 4: Replay-like activity
# ------------------------------------------------------------

replay = base_event.copy()

replay["verification_result"] = 1
replay["replay_indicator"] = 1
replay["time_since_previous"] = 1
replay["verification_frequency"] = 35

scenarios.append(
    ("REPLAY-LIKE ACTIVITY", replay)
)


# ------------------------------------------------------------
# Scenario 5: Certificate problem
# ------------------------------------------------------------

certificate = base_event.copy()

certificate["verification_result"] = 0
certificate["certificate_valid"] = 0
certificate["failed_attempts"] = 5
certificate["failed_verification_rate"] = 0.8

scenarios.append(
    ("CERTIFICATE PROBLEM", certificate)
)


# ------------------------------------------------------------
# Scenario 6: Multiple suspicious indicators
# ------------------------------------------------------------

combined = base_event.copy()

combined["verification_result"] = 0
combined["certificate_valid"] = 0
combined["failed_attempts"] = 10
combined["verification_frequency"] = 35
combined["failed_verification_rate"] = 1.0
combined["source_frequency"] = 50
combined["metadata_anomaly"] = 1
combined["replay_indicator"] = 1

scenarios.append(
    ("MULTIPLE SUSPICIOUS INDICATORS",
     combined)
)


# ============================================================
# RUN TESTS
# ============================================================

results = []


for scenario_name, event in scenarios:

    prediction, probability = predict_event(event)

    risk_score, threat_level, reasons = calculate_risk(
        event
    )

    if threat_level == "HIGH":
        assessment = "HIGH-RISK SECURITY EVENT"

    elif threat_level == "MEDIUM":
        assessment = "SUSPICIOUS SECURITY EVENT"

    elif prediction == "THREAT":
        assessment = "SUSPICIOUS SECURITY EVENT"

    else:
        assessment = "NORMAL SECURITY EVENT"


    print("\n")
    print("=" * 70)
    print("SCENARIO:", scenario_name)
    print("=" * 70)

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


    results.append({
        "scenario": scenario_name,
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

output_file = os.path.join(
    PROJECT_ROOT,
    "data",
    "scenario_test_results.csv"
)

results_df.to_csv(
    output_file,
    index=False
)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n")
print("=" * 70)
print("SCENARIO TEST SUMMARY")
print("=" * 70)

print(
    results_df[
        [
            "scenario",
            "signature_verification",
            "ml_prediction",
            "risk_score",
            "threat_level"
        ]
    ].to_string(index=False)
)

print("\nResults saved to:")
print(output_file)

print("\n")
print("=" * 70)
print("DAY 5 SCENARIO TESTING COMPLETE")
print("=" * 70)