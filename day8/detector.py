import os
import joblib
import pandas as pd


class DigitalSignatureThreatDetector:

    def __init__(self):

        # ----------------------------------------------------
        # Project paths
        # ----------------------------------------------------

        base_dir = os.path.dirname(
            os.path.dirname(
                os.path.abspath(__file__)
            )
        )

        self.model_path = os.path.join(
            base_dir,
            "models",
            "random_forest_day3.pkl"
        )

        # ----------------------------------------------------
        # Load ML model
        # ----------------------------------------------------

        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found:\n{self.model_path}"
            )

        self.model = joblib.load(self.model_path)

        # ----------------------------------------------------
        # Expected model features
        # ----------------------------------------------------

        self.features = [
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


    # ========================================================
    # VALIDATE INPUT
    # ========================================================

    def validate_event(self, event):

        missing = [
            feature
            for feature in self.features
            if feature not in event
        ]

        if missing:
            raise ValueError(
                f"Missing required features: {missing}"
            )

        # Security/data consistency checks

        if not 0 <= event["verification_result"] <= 1:
            raise ValueError(
                "verification_result must be 0 or 1."
            )

        if event["failed_attempts"] < 0:
            raise ValueError(
                "failed_attempts cannot be negative."
            )

        if event["verification_frequency"] < 1:
            raise ValueError(
                "verification_frequency must be at least 1."
            )

        if not 0 <= event["failed_verification_rate"] <= 1:
            raise ValueError(
                "failed_verification_rate must be between 0 and 1."
            )

        if event["failed_attempts"] > event["verification_frequency"]:
            raise ValueError(
                "failed_attempts cannot exceed verification_frequency."
            )

        if event["certificate_valid"] not in [0, 1]:
            raise ValueError(
                "certificate_valid must be 0 or 1."
            )

        if event["metadata_anomaly"] not in [0, 1]:
            raise ValueError(
                "metadata_anomaly must be 0 or 1."
            )

        if event["replay_indicator"] not in [0, 1]:
            raise ValueError(
                "replay_indicator must be 0 or 1."
            )


    # ========================================================
    # ATTACK CATEGORY
    # ========================================================

    def classify_attack(self, event):

        if (
            event["verification_result"] == 0
            and event["metadata_anomaly"] == 1
        ):
            return "DOCUMENT_TAMPERING"

        if event["replay_indicator"] == 1:
            return "REPLAY"

        if (
            event["certificate_valid"] == 0
            and event["verification_result"] == 0
        ):
            return "CERTIFICATE_SECURITY"

        if (
            event["failed_verification_rate"] >= 0.50
            or event["source_frequency"] >= 40
            or event["verification_frequency"] >= 30
        ):
            return "BEHAVIORAL_ANOMALY"

        if event["verification_result"] == 0:
            return "SIGNATURE_VERIFICATION_FAILURE"

        return "BENIGN"


    # ========================================================
    # RISK SCORING
    # ========================================================

    def calculate_risk(self, event):

        score = 0
        reasons = []

        # Signature verification failure
        if event["verification_result"] == 0:
            score += 20
            reasons.append(
                "Digital signature verification failed"
            )

        # Certificate problem
        if event["certificate_valid"] == 0:
            score += 15
            reasons.append(
                "Certificate validation failed"
            )

        # Failure rate
        if event["failed_verification_rate"] >= 0.80:
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
            score += 20
            reasons.append(
                "Possible replay activity detected"
            )

        # Metadata anomaly
        if event["metadata_anomaly"] == 1:
            score += 10
            reasons.append(
                "Suspicious document metadata detected"
            )

        # Source activity
        if event["source_frequency"] >= 40:
            score += 10
            reasons.append(
                "Unusually high verification activity from source"
            )

        # Verification frequency
        if event["verification_frequency"] >= 30:
            score += 10
            reasons.append(
                "Unusually high verification frequency"
            )

        # Keep score within 0-100
        score = min(score, 100)

        # Threat level
        if score >= 70:
            threat_level = "HIGH"

        elif score >= 40:
            threat_level = "MEDIUM"

        else:
            threat_level = "LOW"

        return score, threat_level, reasons


    # ========================================================
    # EXPLANATION
    # ========================================================

    def create_explanation(
        self,
        event,
        ml_prediction,
        probability,
        risk_score,
        reasons
    ):

        explanation = []

        if ml_prediction == 1:
            explanation.append(
                "ML detected suspicious behavioral patterns."
            )
        else:
            explanation.append(
                "ML did not detect a strong threat pattern."
            )

        if event["verification_result"] == 1:
            explanation.append(
                "The current digital signature verification is valid."
            )
        else:
            explanation.append(
                "The current digital signature verification failed."
            )

        if risk_score < 40:
            explanation.append(
                "Rule-based risk indicators remain below "
                "the medium-risk threshold."
            )

        if event["failed_verification_rate"] >= 0.50:
            explanation.append(
                "Historical verification behavior shows "
                "an elevated failure rate."
            )

        if event["replay_indicator"] == 1:
            explanation.append(
                "Replay-like activity was observed."
            )

        return explanation


    # ========================================================
    # MAIN ANALYSIS
    # ========================================================

    def analyze(self, event):

        # Validate input first
        self.validate_event(event)

        # Convert event into DataFrame
        input_data = pd.DataFrame(
            [event],
            columns=self.features
        )

        # ----------------------------------------------------
        # ML prediction
        # ----------------------------------------------------

        prediction = int(
            self.model.predict(input_data)[0]
        )

        probability = float(
            self.model.predict_proba(input_data)[0][1]
        )

        # ----------------------------------------------------
        # Risk scoring
        # ----------------------------------------------------

        risk_score, threat_level, reasons = (
            self.calculate_risk(event)
        )

        # ----------------------------------------------------
        # Attack classification
        # ----------------------------------------------------

        attack_category = self.classify_attack(event)

        # ----------------------------------------------------
        # Explanation
        # ----------------------------------------------------

        explanation = self.create_explanation(
            event,
            prediction,
            probability,
            risk_score,
            reasons
        )

        # ----------------------------------------------------
        # Final assessment
        # ----------------------------------------------------

        if prediction == 1 or risk_score >= 40:
            if threat_level == "HIGH":
                assessment = "HIGH-RISK SECURITY EVENT"
            else:
                assessment = "SUSPICIOUS SECURITY EVENT"

        else:
            assessment = "NORMAL SECURITY EVENT"

        # ----------------------------------------------------
        # Recommended action
        # ----------------------------------------------------

        if threat_level == "HIGH":

            recommendation = [
                "Flag the event immediately.",
                "Review the originating source.",
                "Verify document and certificate integrity.",
                "Investigate possible replay or tampering activity."
            ]

        elif prediction == 1 or risk_score >= 40:

            recommendation = [
                "Flag the event for further investigation.",
                "Continue monitoring the originating source."
            ]

        else:

            recommendation = [
                "No immediate action required.",
                "Continue normal monitoring."
            ]

        return {
            "signature_verification":
                "VALID"
                if event["verification_result"] == 1
                else "INVALID",

            "ml_prediction":
                "THREAT"
                if prediction == 1
                else "NORMAL",

            "ml_threat_probability":
                probability,

            "risk_score":
                risk_score,

            "threat_level":
                threat_level,

            "attack_category":
                attack_category,

            "contributing_indicators":
                reasons,

            "assessment_explanation":
                explanation,

            "final_assessment":
                assessment,

            "recommended_action":
                recommendation
        }