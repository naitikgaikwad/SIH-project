from pathlib import Path
import hashlib
import csv


PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPLAY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed_signatures.csv"
)


def calculate_document_hash(document_data):
    """Create a SHA-256 fingerprint of the document."""
    return hashlib.sha256(document_data).hexdigest()


def check_replay(document_data):
    """
    Check whether this exact document has already been processed.

    Returns:
        True  -> replay detected
        False -> new document
    """

    document_hash = calculate_document_hash(document_data)

    if not REPLAY_FILE.exists():
        return False

    try:

        with open(
            REPLAY_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                if row.get("document_hash") == document_hash:
                    return True

    except Exception as e:

        print("Replay check error:", e)

    return False


def record_document(document_data):
    """
    Store the document fingerprint after processing.
    """

    document_hash = calculate_document_hash(document_data)

    REPLAY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    file_exists = REPLAY_FILE.exists()

    with open(
        REPLAY_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=["document_hash"]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "document_hash": document_hash
        })