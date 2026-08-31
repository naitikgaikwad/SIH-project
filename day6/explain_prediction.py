import os
import joblib
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_FILE = os.path.join(
    BASE_DIR,
    "models",
    "random_forest_day3.pkl"
)

DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "security_events_v3_extended.csv"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 70)
print("DAY 6 - EXPLAINABLE THREAT DETECTION")
print("=" * 70)

if not os.path.exists(MODEL_FILE):
    raise FileNotFoundError(
        f"Model not found:\n{MODEL_FILE}"
    )

if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(
        f"Dataset not found:\n{DATA_FILE}"
    )

model = joblib.load(MODEL_FILE)
data = pd.read_csv(DATA_FILE)

print("\nModel loaded successfully.")
print(f"Dataset records: {len(data)}")


# ============================================================
# SELECT EVENT
# ============================================================

EVENT_INDEX = 0

if EVENT_INDEX >= len(data):
    raise IndexError("Selected event does not exist.")

event = data.iloc[EVENT_INDEX]


# ============================================================
# FEATURE COLUMNS
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


X_event = pd.DataFrame(
    [event[FEATURE_COLUMNS].to_dict()]
)


# ============================================================
# ML PREDICTION
# ============================================================

prediction = int(model.predict(X_event)[0])

probability = float(
    model.predict_proba(X_event)[0][1]
)

if prediction == 1:
    ml_prediction = "THREAT"
else:
    ml_prediction = "NORMAL"


# ============================================================
# RULE-BASED SECURITY INDICATORS
# ============================================================

indicators = []


if event["verification_result"] == 0:
    indicators.append(
        "Digital signature verification failed"
    )


if event["certificate_valid"] == 0:
    indicators.append(
        "Certificate validation failed"
    )


if event["failed_verification_rate"] >= 0.75:
    indicators.append(
        "Very high signature verification failure rate"
    )
elif event["failed_verification_rate"] >= 0.50:
    indicators.append(
        "High signature verification failure rate"
    )


if event["replay_indicator"] == 1:
    indicators.append(
        "Possible replay activity detected"
    )


if event["metadata_anomaly"] == 1:
    indicators.append(
        "Suspicious document metadata detected"
    )


if event["source_frequency"] >= 40:
    indicators.append(
        "Unusually high verification activity from source"
    )


if event["verification_frequency"] >= 30:
    indicators.append(
        "Unusually high verification frequency"
    )


# ============================================================
# RISK SCORE
# ============================================================

risk_score = 0

if event["verification_result"] == 0:
    risk_score += 20

if event["certificate_valid"] == 0:
    risk_score += 15

if event["failed_verification_rate"] >= 0.75:
    risk_score += 20
elif event["failed_verification_rate"] >= 0.50:
    risk_score += 10

if event["replay_indicator"] == 1:
    risk_score += 15

if event["metadata_anomaly"] == 1:
    risk_score += 10

if event["source_frequency"] >= 40:
    risk_score += 10

if event["verification_frequency"] >= 30:
    risk_score += 10


risk_score = min(risk_score, 100)


# ============================================================
# THREAT LEVEL
# ============================================================

if risk_score >= 70:
    threat_level = "HIGH"
elif risk_score >= 40:
    threat_level = "MEDIUM"
else:
    threat_level = "LOW"


# ============================================================
# SECURITY ASSESSMENT
# ============================================================

if ml_prediction == "THREAT" or risk_score >= 40:
    if threat_level == "HIGH":
        assessment = "HIGH-RISK SECURITY EVENT"
    else:
        assessment = "SUSPICIOUS SECURITY EVENT"
else:
    assessment = "NORMAL SECURITY EVENT"


# ============================================================
# EXPLANATION
# ============================================================

print("\n")
print("=" * 70)
print("THREAT DETECTION RESULT")
print("=" * 70)

print(
    f"\nSignature Verification : "
    f"{'VALID' if event['verification_result'] == 1 else 'INVALID'}"
)

print(
    f"ML Prediction          : {ml_prediction}"
)

print(
    f"ML Threat Probability  : {probability * 100:.2f}%"
)

print(
    f"Risk Score             : {risk_score} / 100"
)

print(
    f"Threat Level           : {threat_level}"
)


# ============================================================
# CONTRIBUTING INDICATORS
# ============================================================

print("\nContributing Indicators:")

if indicators:
    for indicator in indicators:
        print(f" - {indicator}")
else:
    print(" - None")


# ============================================================
# EXPLANATION SECTION
# ============================================================

print("\nAssessment Explanation:")

if ml_prediction == "THREAT":
    print(
        " - ML detected suspicious behavioral patterns."
    )
else:
    print(
        " - ML did not classify the event as a threat."
    )


if event["verification_result"] == 1:
    print(
        " - The current digital signature verification is valid."
    )
else:
    print(
        " - The current digital signature verification failed."
    )


if risk_score < 40:
    print(
        " - Rule-based risk indicators remain below the medium-risk threshold."
    )
elif risk_score < 70:
    print(
        " - Rule-based indicators indicate a medium level of security risk."
    )
else:
    print(
        " - Multiple rule-based indicators indicate high security risk."
    )


if event["failed_verification_rate"] >= 0.75:
    print(
        " - Historical verification behavior shows a very high failure rate."
    )


if event["replay_indicator"] == 1:
    print(
        " - Replay-related activity was detected in the event data."
    )


if event["metadata_anomaly"] == 1:
    print(
        " - Anomalous document metadata was detected."
    )


# ============================================================
# RECOMMENDED ACTION
# ============================================================

print("\nRecommended Action:")

if threat_level == "HIGH":
    print(
        " - Escalate the event for immediate security investigation."
    )
    print(
        " - Review the originating source and associated security events."
    )

elif threat_level == "MEDIUM":
    print(
        " - Flag the event for further investigation."
    )
    print(
        " - Continue monitoring the originating source."
    )

else:
    if ml_prediction == "THREAT":
        print(
            " - Flag the event for further investigation."
        )
        print(
            " - Continue monitoring the originating source."
        )
    else:
        print(
            " - No immediate action required."
        )
        print(
            " - Continue normal monitoring."
        )


# ============================================================
# COMPLETE
# ============================================================

print("\n")
print("=" * 70)
print("EXPLAINABILITY ANALYSIS COMPLETE")
print("=" * 70)