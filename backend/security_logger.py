import csv
from pathlib import Path
from datetime import datetime


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "data" / "security_events_runtime.csv"


# ============================================================
# CSV COLUMNS
# ============================================================

FIELDS = [
    "timestamp",
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
    "time_since_previous",
    "threat",
    "risk_score",
    "threat_level",
    "attack_category"
]


# ============================================================
# INITIALIZE LOG FILE
# ============================================================

def initialize_log():

    LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if not LOG_FILE.exists():

        with open(
            LOG_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=FIELDS
            )

            writer.writeheader()


# ============================================================
# LOG SECURITY EVENT
# ============================================================

def log_security_event(
    event,
    ml_result
):

    initialize_log()

    row = {

        "timestamp":
            datetime.now().isoformat(
                timespec="seconds"
            ),

        "verification_result":
            event.get(
                "verification_result",
                0
            ),

        "failed_attempts":
            event.get(
                "failed_attempts",
                0
            ),

        "verification_frequency":
            event.get(
                "verification_frequency",
                0
            ),

        "key_size":
            event.get(
                "key_size",
                0
            ),

        "algorithm":
            event.get(
                "algorithm",
                ""
            ),

        "hour":
            event.get(
                "hour",
                0
            ),

        "signature_size":
            event.get(
                "signature_size",
                0
            ),

        "certificate_valid":
            event.get(
                "certificate_valid",
                0
            ),

        "source_frequency":
            event.get(
                "source_frequency",
                0
            ),

        "failed_verification_rate":
            event.get(
                "failed_verification_rate",
                0
            ),

        "document_size":
            event.get(
                "document_size",
                0
            ),

        "metadata_anomaly":
            event.get(
                "metadata_anomaly",
                0
            ),

        "replay_indicator":
            event.get(
                "replay_indicator",
                0
            ),

        "key_age_days":
            event.get(
                "key_age_days",
                0
            ),

        "time_since_previous":
            event.get(
                "time_since_previous",
                0
            ),

        "threat":
            (
                1
                if ml_result.get(
                    "ml_prediction"
                ) == "THREAT"
                else 0
            ),

        "risk_score":
            ml_result.get(
                "risk_score",
                0
            ),

        "threat_level":
            ml_result.get(
                "threat_level",
                "LOW"
            ),

        "attack_category":
            ml_result.get(
                "attack_category",
                "BENIGN"
            )
    }


    with open(
        LOG_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=FIELDS
        )

        writer.writerow(row)


# ============================================================
# GET LOG FILE PATH
# ============================================================

def get_log_file():

    initialize_log()

    return LOG_FILE