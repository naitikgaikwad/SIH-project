import os
import joblib
import pandas as pd


# =========================================================
# PROJECT PATH
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =========================================================
# QI MODEL PATH
# =========================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "random_forest_qi_day7.pkl"
)


# =========================================================
# QI-SELECTED FEATURES
# =========================================================

QI_FEATURES = [
    "verification_result",
    "failed_attempts",
    "certificate_valid",
    "source_frequency",
    "failed_verification_rate",
    "metadata_anomaly",
    "replay_indicator"
]


# =========================================================
# LOAD MODEL
# =========================================================

if not os.path.exists(MODEL_PATH):

    raise FileNotFoundError(
        f"QI model not found:\n{MODEL_PATH}"
    )


model = joblib.load(
    MODEL_PATH
)


# =========================================================
# RISK SCORING
# =========================================================

def calculate_risk_score(event):

    score = 0

    reasons = []


    # -----------------------------------------------------
    # Signature verification
    # -----------------------------------------------------

    if event.get(
        "verification_result"
    ) == 0:

        score += 25

        reasons.append(
            "Digital signature verification failed"
        )


    # -----------------------------------------------------
    # Certificate validation
    # -----------------------------------------------------

    if event.get(
        "certificate_valid"
    ) == 0:

        score += 15

        reasons.append(
            "Certificate validation failed"
        )


    # -----------------------------------------------------
    # Historical failure rate
    # -----------------------------------------------------

    failure_rate = event.get(
        "failed_verification_rate",
        0
    )


    if failure_rate >= 0.7:

        score += 20

        reasons.append(
            "Very high signature verification failure rate"
        )

    elif failure_rate >= 0.5:

        score += 10

        reasons.append(
            "High signature verification failure rate"
        )


    # -----------------------------------------------------
    # Replay indicator
    # -----------------------------------------------------

    if event.get(
        "replay_indicator"
    ) == 1:

        score += 15

        reasons.append(
            "Possible replay activity detected"
        )


    # -----------------------------------------------------
    # Metadata anomaly
    # -----------------------------------------------------

    if event.get(
        "metadata_anomaly"
    ) == 1:

        score += 10

        reasons.append(
            "Suspicious document metadata detected"
        )


    # -----------------------------------------------------
    # Source frequency
    # -----------------------------------------------------

    source_frequency = event.get(
        "source_frequency",
        0
    )


    if source_frequency >= 40:

        score += 10

        reasons.append(
            "Unusually high verification activity from source"
        )


    # -----------------------------------------------------
    # Verification frequency
    # -----------------------------------------------------

    verification_frequency = event.get(
        "verification_frequency",
        0
    )


    if verification_frequency >= 30:

        score += 5

        reasons.append(
            "Unusually high verification frequency"
        )


    # -----------------------------------------------------
    # Limit score
    # -----------------------------------------------------

    score = min(
        score,
        100
    )


    # -----------------------------------------------------
    # Threat level
    # -----------------------------------------------------

    if score >= 70:

        threat_level = "HIGH"

    elif score >= 40:

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"


    return (
        score,
        threat_level,
        reasons
    )


# =========================================================
# ATTACK CATEGORY
# =========================================================

def determine_attack_category(event):

    indicator_count = 0


    if event.get(
        "verification_result"
    ) == 0:

        indicator_count += 1


    if event.get(
        "certificate_valid"
    ) == 0:

        indicator_count += 1


    if event.get(
        "failed_verification_rate",
        0
    ) >= 0.7:

        indicator_count += 1


    if event.get(
        "replay_indicator"
    ) == 1:

        indicator_count += 1


    if event.get(
        "metadata_anomaly"
    ) == 1:

        indicator_count += 1


    if event.get(
        "source_frequency",
        0
    ) >= 40:

        indicator_count += 1


    if event.get(
        "verification_frequency",
        0
    ) >= 30:

        indicator_count += 1


    # -----------------------------------------------------
    # Combined threat
    # -----------------------------------------------------

    if indicator_count >= 4:

        return "COMBINED_THREAT"


    # -----------------------------------------------------
    # Document tampering
    # -----------------------------------------------------

    if (
        event.get(
            "verification_result"
        ) == 0

        and

        event.get(
            "certificate_valid"
        ) == 1
    ):

        return "DOCUMENT_TAMPERING"


    # -----------------------------------------------------
    # Replay
    # -----------------------------------------------------

    if event.get(
        "replay_indicator"
    ) == 1:

        return "REPLAY"


    # -----------------------------------------------------
    # Certificate security
    # -----------------------------------------------------

    if event.get(
        "certificate_valid"
    ) == 0:

        return "CERTIFICATE_SECURITY"


    # -----------------------------------------------------
    # Behavioral anomaly
    # -----------------------------------------------------

    if (
        event.get(
            "failed_verification_rate",
            0
        ) >= 0.7

        or

        event.get(
            "source_frequency",
            0
        ) >= 40

        or

        event.get(
            "verification_frequency",
            0
        ) >= 30
    ):

        return "BEHAVIORAL_ANOMALY"


    return "BENIGN"


# =========================================================
# EXPLANATION
# =========================================================

def generate_explanation(
    event,
    prediction,
    risk_score
):

    explanation = []


    # -----------------------------------------------------
    # ML result
    # -----------------------------------------------------

    if prediction == 1:

        explanation.append(
            "ML detected suspicious behavioral patterns."
        )

    else:

        explanation.append(
            "ML did not detect a strong threat pattern."
        )


    # -----------------------------------------------------
    # Signature result
    # -----------------------------------------------------

    if event.get(
        "verification_result"
    ) == 1:

        explanation.append(
            "The current digital signature verification is valid."
        )

    else:

        explanation.append(
            "The current digital signature verification failed."
        )


    # -----------------------------------------------------
    # Risk interpretation
    # -----------------------------------------------------

    if risk_score < 40:

        explanation.append(
            "Rule-based risk indicators remain below "
            "the medium-risk threshold."
        )

    elif risk_score < 70:

        explanation.append(
            "Rule-based indicators indicate a "
            "medium-risk security event."
        )

    else:

        explanation.append(
            "Multiple rule-based indicators indicate "
            "a high-risk security event."
        )


    # -----------------------------------------------------
    # Failure behavior
    # -----------------------------------------------------

    if event.get(
        "failed_verification_rate",
        0
    ) >= 0.7:

        explanation.append(
            "Historical verification behavior shows "
            "a high failure rate."
        )


    # -----------------------------------------------------
    # Replay
    # -----------------------------------------------------

    if event.get(
        "replay_indicator"
    ) == 1:

        explanation.append(
            "Replay-like activity was observed."
        )


    # -----------------------------------------------------
    # Metadata
    # -----------------------------------------------------

    if event.get(
        "metadata_anomaly"
    ) == 1:

        explanation.append(
            "Suspicious document metadata was observed."
        )


    return explanation


# =========================================================
# RECOMMENDED ACTION
# =========================================================

def generate_recommended_action(
    threat_level,
    prediction
):

    if threat_level == "HIGH":

        return [
            "Flag the event immediately.",
            "Review the originating source.",
            "Verify document and certificate integrity.",
            "Investigate possible replay or tampering activity."
        ]


    if (
        threat_level == "MEDIUM"
        or prediction == 1
    ):

        return [
            "Flag the event for further investigation.",
            "Continue monitoring the originating source."
        ]


    return [
        "No immediate action required.",
        "Continue normal monitoring."
    ]


# =========================================================
# MAIN THREAT DETECTION FUNCTION
# =========================================================

def detect_threat(event):

    # -----------------------------------------------------
    # Create DataFrame from security event
    # -----------------------------------------------------

    dataframe = pd.DataFrame(
        [event]
    )


    # -----------------------------------------------------
    # Check required QI features
    # -----------------------------------------------------

    missing_features = [
        feature
        for feature in QI_FEATURES
        if feature not in dataframe.columns
    ]


    if missing_features:

        raise ValueError(
            "Missing QI model features: "
            + ", ".join(missing_features)
        )


    # -----------------------------------------------------
    # IMPORTANT:
    # Use ONLY the 7 features used during QI training
    # -----------------------------------------------------

    dataframe = dataframe[
        QI_FEATURES
    ]


    # -----------------------------------------------------
    # ML prediction
    # -----------------------------------------------------

    prediction = int(
        model.predict(
            dataframe
        )[0]
    )


    # -----------------------------------------------------
    # ML threat probability
    # -----------------------------------------------------

    probability = float(
        model.predict_proba(
            dataframe
        )[0][1]
    )


    # -----------------------------------------------------
    # Rule-based risk scoring
    # -----------------------------------------------------

    risk_score, threat_level, reasons = (
        calculate_risk_score(
            event
        )
    )


    # -----------------------------------------------------
    # Attack category
    # -----------------------------------------------------

    attack_category = (
        determine_attack_category(
            event
        )
    )


    # -----------------------------------------------------
    # Assessment
    # -----------------------------------------------------

    if (
        prediction == 1
        and risk_score >= 70
    ):

        assessment = (
            "HIGH-RISK SECURITY EVENT"
        )

    elif (
        prediction == 1
        or risk_score >= 40
    ):

        assessment = (
            "SUSPICIOUS SECURITY EVENT"
        )

    else:

        assessment = (
            "NORMAL SECURITY EVENT"
        )


    # -----------------------------------------------------
    # Explanation
    # -----------------------------------------------------

    explanation = generate_explanation(
        event,
        prediction,
        risk_score
    )


    # -----------------------------------------------------
    # Recommended action
    # -----------------------------------------------------

    recommended_action = (
        generate_recommended_action(
            threat_level,
            prediction
        )
    )


    # -----------------------------------------------------
    # Final result
    # -----------------------------------------------------

    return {

        "signature_verification":
            (
                "VALID"
                if event.get(
                    "verification_result"
                ) == 1
                else "INVALID"
            ),

        "ml_prediction":
            (
                "THREAT"
                if prediction == 1
                else "NORMAL"
            ),

        "ml_threat_probability":
            round(
                probability * 100,
                2
            ),

        "risk_score":
            risk_score,

        "threat_level":
            threat_level,

        "attack_category":
            attack_category,

        "contributing_indicators":
            reasons,

        "assessment":
            assessment,

        "assessment_explanation":
            explanation,

        "recommended_action":
            recommended_action
    }