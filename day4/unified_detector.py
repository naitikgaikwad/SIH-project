import os
import joblib
import pandas as pd


# ============================================================
# PATH CONFIGURATION
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
# LOAD MODEL
# ============================================================

print("=" * 70)
print("UNIFIED DIGITAL SIGNATURE THREAT DETECTOR")
print("=" * 70)

if not os.path.exists(MODEL_FILE):
    print("\nERROR: Model file not found.")
    print("Expected location:")
    print(MODEL_FILE)
    raise SystemExit

if not os.path.exists(DATA_FILE):
    print("\nERROR: Dataset file not found.")
    print("Expected location:")
    print(DATA_FILE)
    raise SystemExit


model = joblib.load(MODEL_FILE)
data = pd.read_csv(DATA_FILE)

print("\nModel loaded successfully.")
print("Dataset records:", len(data))


# ============================================================
# RISK SCORING ENGINE
# ============================================================

def calculate_risk_score(event):
    """
    Calculate a rule-based security risk score.

    Maximum score = 100.
    The score is based on observable security indicators.
    """

    score = 0
    reasons = []

    # --------------------------------------------------------
    # 1. Signature verification
    # --------------------------------------------------------

    if event["verification_result"] == 0:
        score += 25
        reasons.append(
            "Digital signature verification failed"
        )

    # --------------------------------------------------------
    # 2. Certificate validation
    # --------------------------------------------------------

    if event["certificate_valid"] == 0:
        score += 15
        reasons.append(
            "Certificate validation failed"
        )

    # --------------------------------------------------------
    # 3. Verification failure rate
    # --------------------------------------------------------

    failure_rate = event["failed_verification_rate"]

    if failure_rate >= 0.75:
        score += 20
        reasons.append(
            "Very high signature verification failure rate"
        )

    elif failure_rate >= 0.50:
        score += 10
        reasons.append(
            "High signature verification failure rate"
        )

    # --------------------------------------------------------
    # 4. Replay indicator
    # --------------------------------------------------------

    if event["replay_indicator"] == 1:
        score += 15
        reasons.append(
            "Possible replay activity detected"
        )

    # --------------------------------------------------------
    # 5. Metadata anomaly
    # --------------------------------------------------------

    if event["metadata_anomaly"] == 1:
        score += 10
        reasons.append(
            "Suspicious document metadata detected"
        )

    # --------------------------------------------------------
    # 6. Source activity
    # --------------------------------------------------------

    if event["source_frequency"] >= 40:
        score += 10
        reasons.append(
            "Unusually high verification activity from the source"
        )

    elif event["source_frequency"] >= 30:
        score += 5
        reasons.append(
            "Elevated verification activity from the source"
        )

    # --------------------------------------------------------
    # 7. Verification frequency
    # --------------------------------------------------------

    if event["verification_frequency"] >= 30:
        score += 5
        reasons.append(
            "Unusually high verification frequency"
        )

    # --------------------------------------------------------
    # Keep score between 0 and 100
    # --------------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------------
    # Threat level
    # --------------------------------------------------------

    if score >= 70:
        threat_level = "HIGH"

    elif score >= 40:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    return score, threat_level, reasons


# ============================================================
# SELECT EVENT
# ============================================================

event_index = 0

if event_index >= len(data):
    print("\nERROR: Event index is outside the dataset.")
    raise SystemExit


event = data.iloc[event_index]


print("\n")
print("Analyzing event:", event_index)


# ============================================================
# PREPARE DATA FOR ML MODEL
# ============================================================

# Keep the same columns used during model training.
feature_columns = [
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

event_data = pd.DataFrame(
    [event[feature_columns].to_dict()]
)


# ============================================================
# ML PREDICTION
# ============================================================

prediction = model.predict(event_data)[0]

probabilities = model.predict_proba(event_data)[0]

# Probability corresponding to class 1 (THREAT)
threat_probability = 0.0

for class_value, probability in zip(
    model.classes_,
    probabilities
):
    if class_value == 1:
        threat_probability = probability


ml_prediction = "THREAT" if prediction == 1 else "NORMAL"


# ============================================================
# RULE-BASED RISK ANALYSIS
# ============================================================

risk_score, threat_level, reasons = calculate_risk_score(event)


# ============================================================
# FINAL ASSESSMENT
# ============================================================

if threat_level == "HIGH":
    final_assessment = "HIGH-RISK SECURITY EVENT"

elif threat_level == "MEDIUM":
    final_assessment = "SUSPICIOUS SECURITY EVENT"

elif ml_prediction == "THREAT":
    final_assessment = "SUSPICIOUS SECURITY EVENT"

else:
    final_assessment = "NORMAL SECURITY EVENT"


# ============================================================
# EXPLANATION
# ============================================================

explanations = []

if ml_prediction == "THREAT":
    explanations.append(
        "ML detected suspicious behavioral patterns."
    )

else:
    explanations.append(
        "ML model did not detect strong threat patterns."
    )


if event["verification_result"] == 1:
    explanations.append(
        "The current digital signature verification is valid."
    )

else:
    explanations.append(
        "The current digital signature verification failed."
    )


if risk_score < 40 and ml_prediction == "THREAT":
    explanations.append(
        "ML detected suspicious behavior even though "
        "the rule-based risk score is currently low."
    )

elif risk_score >= 40:
    explanations.append(
        "Multiple security indicators contributed to the "
        "elevated rule-based risk score."
    )

if event["failed_verification_rate"] >= 0.75:
    explanations.append(
        "Historical verification behavior shows a very high "
        "failure rate."
    )


# ============================================================
# RECOMMENDED ACTION
# ============================================================

if threat_level == "HIGH":

    recommended_actions = [
        "Flag the event immediately.",
        "Investigate the originating source.",
        "Verify certificate and signature integrity.",
        "Check for possible replay or metadata anomalies."
    ]

elif threat_level == "MEDIUM":

    recommended_actions = [
        "Flag the event for investigation.",
        "Review the originating source activity.",
        "Monitor subsequent verification attempts."
    ]

elif ml_prediction == "THREAT":

    recommended_actions = [
        "Flag the event for further investigation.",
        "Continue monitoring the originating source.",
        "Review historical verification behavior."
    ]

else:

    recommended_actions = [
        "Allow the event under normal monitoring.",
        "Continue routine security monitoring."
    ]


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 70)
print("THREAT DETECTION RESULT")
print("=" * 70)

print(
    "\nSignature Verification :",
    "VALID" if event["verification_result"] == 1 else "INVALID"
)

print(
    "ML Prediction          :",
    ml_prediction
)

print(
    "ML Threat Probability  :",
    f"{threat_probability * 100:.2f}%"
)

print(
    "Risk Score             :",
    f"{risk_score} / 100"
)

print(
    "Threat Level           :",
    threat_level
)


# ============================================================
# CONTRIBUTING INDICATORS
# ============================================================

print("\nContributing Indicators:")

if reasons:

    for reason in reasons:
        print(" -", reason)

else:

    print(" - No significant rule-based indicators detected.")


# ============================================================
# FINAL ASSESSMENT
# ============================================================

print(
    "\nFinal Assessment       :",
    final_assessment
)


# ============================================================
# ASSESSMENT EXPLANATION
# ============================================================

print("\nAssessment Explanation:")

for explanation in explanations:
    print(" -", explanation)


# ============================================================
# RECOMMENDED ACTION
# ============================================================

print("\nRecommended Action:")

for action in recommended_actions:
    print(" -", action)


print("\n")
print("=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)