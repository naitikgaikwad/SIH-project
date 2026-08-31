import sys
import os

# Allow Python to find detector.py
sys.path.append(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

from detector import DigitalSignatureThreatDetector


print("=" * 70)
print("DAY 8 - INTEGRATED THREAT DETECTOR TEST")
print("=" * 70)


# ============================================================
# LOAD DETECTOR
# ============================================================

detector = DigitalSignatureThreatDetector()

print("\nModel loaded successfully.")


# ============================================================
# TEST SCENARIOS
# ============================================================

scenarios = {

    "NORMAL EVENT": {
        "verification_result": 1,
        "failed_attempts": 0,
        "verification_frequency": 5,
        "key_size": 2048,
        "algorithm": "RSA-PSS",
        "hour": 10,
        "signature_size": 512,
        "certificate_valid": 1,
        "source_frequency": 5,
        "failed_verification_rate": 0.0,
        "document_size": 1000,
        "metadata_anomaly": 0,
        "replay_indicator": 0,
        "key_age_days": 300,
        "time_since_previous": 500
    },


    "DOCUMENT TAMPERING": {
        "verification_result": 0,
        "failed_attempts": 8,
        "verification_frequency": 10,
        "key_size": 2048,
        "algorithm": "RSA-PSS",
        "hour": 14,
        "signature_size": 512,
        "certificate_valid": 1,
        "source_frequency": 15,
        "failed_verification_rate": 0.8,
        "document_size": 1200,
        "metadata_anomaly": 1,
        "replay_indicator": 0,
        "key_age_days": 300,
        "time_since_previous": 100
    },


    "REPLAY ACTIVITY": {
        "verification_result": 1,
        "failed_attempts": 1,
        "verification_frequency": 32,
        "key_size": 2048,
        "algorithm": "RSA-PSS",
        "hour": 15,
        "signature_size": 512,
        "certificate_valid": 1,
        "source_frequency": 45,
        "failed_verification_rate": 0.1,
        "document_size": 1000,
        "metadata_anomaly": 0,
        "replay_indicator": 1,
        "key_age_days": 300,
        "time_since_previous": 5
    },


    "CERTIFICATE PROBLEM": {
        "verification_result": 0,
        "failed_attempts": 7,
        "verification_frequency": 10,
        "key_size": 2048,
        "algorithm": "RSA-PSS",
        "hour": 12,
        "signature_size": 512,
        "certificate_valid": 0,
        "source_frequency": 20,
        "failed_verification_rate": 0.7,
        "document_size": 1000,
        "metadata_anomaly": 0,
        "replay_indicator": 0,
        "key_age_days": 500,
        "time_since_previous": 200
    },


    "COMBINED THREAT": {
        "verification_result": 0,
        "failed_attempts": 10,
        "verification_frequency": 35,
        "key_size": 2048,
        "algorithm": "RSA-PSS",
        "hour": 3,
        "signature_size": 512,
        "certificate_valid": 0,
        "source_frequency": 50,
        "failed_verification_rate": 1.0,
        "document_size": 4000,
        "metadata_anomaly": 1,
        "replay_indicator": 1,
        "key_age_days": 1500,
        "time_since_previous": 2
    }
}


# ============================================================
# RUN TESTS
# ============================================================

for scenario_name, event in scenarios.items():

    print("\n")
    print("=" * 70)
    print("SCENARIO:", scenario_name)
    print("=" * 70)

    try:

        result = detector.analyze(event)

        print(
            "\nSignature Verification :",
            result["signature_verification"]
        )

        print(
            "ML Prediction          :",
            result["ml_prediction"]
        )

        print(
            "ML Threat Probability  :",
            f"{result['ml_threat_probability'] * 100:.2f}%"
        )

        print(
            "Risk Score             :",
            f"{result['risk_score']} / 100"
        )

        print(
            "Threat Level           :",
            result["threat_level"]
        )

        print(
            "Attack Category        :",
            result["attack_category"]
        )

        print("\nContributing Indicators:")

        if result["contributing_indicators"]:

            for reason in result["contributing_indicators"]:
                print(" -", reason)

        else:
            print(" - None")

        print("\nAssessment Explanation:")

        for explanation in result["assessment_explanation"]:
            print(" -", explanation)

        print(
            "\nFinal Assessment       :",
            result["final_assessment"]
        )

        print("\nRecommended Action:")

        for action in result["recommended_action"]:
            print(" -", action)

    except Exception as error:

        print("\nERROR:")
        print(error)


print("\n")
print("=" * 70)
print("DAY 8 INTEGRATED TEST COMPLETE")
print("=" * 70)