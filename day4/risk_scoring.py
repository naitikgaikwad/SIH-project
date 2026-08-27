from dataclasses import dataclass


# ============================================================
# RISK RESULT
# ============================================================

@dataclass
class RiskResult:

    score: float
    level: str
    reasons: list


# ============================================================
# RISK SCORING FUNCTION
# ============================================================

def calculate_risk(event):

    score = 0

    reasons = []


    # --------------------------------------------------------
    # 1. SIGNATURE VERIFICATION
    # --------------------------------------------------------

    if event["verification_result"] == 0:

        score += 30

        reasons.append(
            "Digital signature verification failed"
        )


    # --------------------------------------------------------
    # 2. CERTIFICATE VALIDITY
    # --------------------------------------------------------

    if event["certificate_valid"] == 0:

        score += 20

        reasons.append(
            "Certificate validation failed"
        )


    # --------------------------------------------------------
    # 3. FAILED VERIFICATION RATE
    # --------------------------------------------------------

    failure_rate = event[
        "failed_verification_rate"
    ]


    if failure_rate >= 0.75:

        score += 20

        reasons.append(
            "Very high signature verification failure rate"
        )

    elif failure_rate >= 0.50:

        score += 15

        reasons.append(
            "High signature verification failure rate"
        )

    elif failure_rate >= 0.25:

        score += 8

        reasons.append(
            "Elevated signature verification failure rate"
        )


    # --------------------------------------------------------
    # 4. REPLAY INDICATOR
    # --------------------------------------------------------

    if event["replay_indicator"] == 1:

        score += 15

        reasons.append(
            "Possible replay activity detected"
        )


    # --------------------------------------------------------
    # 5. METADATA ANOMALY
    # --------------------------------------------------------

    if event["metadata_anomaly"] == 1:

        score += 10

        reasons.append(
            "Suspicious document metadata detected"
        )


    # --------------------------------------------------------
    # 6. SOURCE FREQUENCY
    # --------------------------------------------------------

    source_frequency = event[
        "source_frequency"
    ]


    if source_frequency >= 40:

        score += 10

        reasons.append(
            "Unusually high verification activity "
            "from the source"
        )

    elif source_frequency >= 30:

        score += 5

        reasons.append(
            "Elevated verification activity "
            "from the source"
        )


    # --------------------------------------------------------
    # 7. VERIFICATION FREQUENCY
    # --------------------------------------------------------

    verification_frequency = event[
        "verification_frequency"
    ]


    if verification_frequency >= 30:

        score += 5

        reasons.append(
            "Unusually high verification frequency"
        )


    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    score = min(
        score,
        100
    )


    # --------------------------------------------------------
    # THREAT LEVEL
    # --------------------------------------------------------

    if score >= 70:

        level = "HIGH"

    elif score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"


    return RiskResult(

        score=score,

        level=level,

        reasons=reasons
    )


# ============================================================
# TEST EVENTS
# ============================================================

if __name__ == "__main__":


    print("=" * 60)

    print("DIGITAL SIGNATURE SECURITY")
    print("RISK SCORING ENGINE")

    print("=" * 60)


    # --------------------------------------------------------
    # NORMAL EVENT
    # --------------------------------------------------------

    normal_event = {

        "verification_result": 1,

        "verification_frequency": 10,

        "certificate_valid": 1,

        "source_frequency": 12,

        "failed_verification_rate": 0.10,

        "metadata_anomaly": 0,

        "replay_indicator": 0
    }


    result = calculate_risk(
        normal_event
    )


    print("\nNORMAL EVENT")

    print(
        "Risk Score:",
        result.score
    )

    print(
        "Threat Level:",
        result.level
    )

    print(
        "Reasons:",
        result.reasons
    )


    # --------------------------------------------------------
    # SUSPICIOUS EVENT
    # --------------------------------------------------------

    suspicious_event = {

        "verification_result": 0,

        "verification_frequency": 32,

        "certificate_valid": 0,

        "source_frequency": 45,

        "failed_verification_rate": 0.80,

        "metadata_anomaly": 1,

        "replay_indicator": 1
    }


    result = calculate_risk(
        suspicious_event
    )


    print("\nSUSPICIOUS EVENT")

    print(
        "Risk Score:",
        result.score
    )

    print(
        "Threat Level:",
        result.level
    )

    print(
        "Reasons:"
    )


    for reason in result.reasons:

        print(
            " -",
            reason
        )


    print("\n")

    print("=" * 60)

    print("RISK SCORING TEST COMPLETE")

    print("=" * 60)