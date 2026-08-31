
from pathlib import Path
import csv
from datetime import datetime


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "security_events_runtime.csv"
)


# ============================================================
# LOAD PREVIOUS EVENTS
# ============================================================

def load_events():

    if not LOG_FILE.exists():
        return []

    try:

        with open(
            LOG_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            return list(reader)

    except Exception:

        return []


# ============================================================
# CALCULATE BEHAVIORAL FEATURES
# ============================================================

def calculate_behavioral_features(
    current_verification_result,
    source_id="default_source"
):

    events = load_events()


    # ========================================================
    # CURRENT TIME
    # ========================================================

    current_time = datetime.now()

    current_hour = current_time.hour


    # ========================================================
    # NO PREVIOUS HISTORY
    # ========================================================

    if not events:

        return {

            "verification_frequency": 1,

            "source_frequency": 1,

            "failed_verification_rate":
                0.0
                if current_verification_result == 1
                else 1.0,

            "time_since_previous": 0,

            "hour": current_hour
        }


    # ========================================================
    # VERIFICATION FREQUENCY
    # ========================================================

    verification_frequency = (
        len(events) + 1
    )


    # ========================================================
    # FAILED VERIFICATION COUNT
    # ========================================================

    failed_events = 0

    for event in events:

        try:

            if int(
                event.get(
                    "verification_result",
                    1
                )
            ) == 0:

                failed_events += 1

        except (
            ValueError,
            TypeError
        ):

            continue


    # Include current event

    if current_verification_result == 0:

        failed_events += 1


    # ========================================================
    # FAILED VERIFICATION RATE
    # ========================================================

    failed_verification_rate = (
        failed_events
        / verification_frequency
    )


    # ========================================================
    # SOURCE FREQUENCY
    # ========================================================
    #
    # Count previous events belonging to this source.
    #
    # Older runtime logs may not contain source_id, so those
    # records are ignored for source-specific counting.
    #

    source_frequency = 1

    for event in events:

        if event.get(
            "source_id",
            ""
        ) == source_id:

            source_frequency += 1


    # ========================================================
    # TIME SINCE PREVIOUS EVENT
    # ========================================================

    time_since_previous = 0

    try:

        previous_timestamp = events[-1].get(
            "timestamp"
        )

        if previous_timestamp:

            previous_time = datetime.fromisoformat(
                previous_timestamp
            )

            difference = (
                current_time
                - previous_time
            )

            time_since_previous = max(
                0,
                int(
                    difference.total_seconds()
                )
            )

    except Exception:

        time_since_previous = 0


    # ========================================================
    # RETURN FEATURES
    # ========================================================

    return {

        "verification_frequency":
            verification_frequency,

        "source_frequency":
            source_frequency,

        "failed_verification_rate":
            round(
                failed_verification_rate,
                4
            ),

        "time_since_previous":
            time_since_previous,

        "hour":
            current_hour
    }
