from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path
import sys


# ============================================================
# PATH SETUP
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent

if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))


# ============================================================
# IMPORT COMPONENTS
# ============================================================

try:

    from backend.detector import detect_threat

    from backend.security_logger import (
        log_security_event
    )

    from backend.behavioral_features import (
        calculate_behavioral_features
    )

    from backend.replay_detector import (
        check_replay,
        record_document
    )

    print("=" * 70)
    print("THREAT DETECTOR LOADED SUCCESSFULLY")
    print("SECURITY LOGGER LOADED SUCCESSFULLY")
    print("BEHAVIORAL FEATURE ENGINE LOADED SUCCESSFULLY")
    print("REPLAY DETECTOR LOADED SUCCESSFULLY")
    print("=" * 70)

except Exception as e:

    detect_threat = None
    log_security_event = None
    calculate_behavioral_features = None
    check_replay = None
    record_document = None

    print("=" * 70)
    print("BACKEND IMPORT ERROR")
    print("=" * 70)
    print("Error type :", type(e).__name__)
    print("Error      :", str(e))
    print("=" * 70)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Digital Signature Security Threat Detector",
    description="SIH26141 Digital Signature Security API",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# INPUT MODEL
# ============================================================

class SecurityEvent(BaseModel):

    verification_result: int = Field(..., ge=0, le=1)

    failed_attempts: int = Field(..., ge=0)

    verification_frequency: int = Field(..., ge=1)

    key_size: int = Field(..., gt=0)

    algorithm: str

    hour: int = Field(..., ge=0, le=23)

    signature_size: int = Field(..., gt=0)

    certificate_valid: int = Field(..., ge=0, le=1)

    source_frequency: int = Field(..., ge=0)

    failed_verification_rate: float = Field(
        ...,
        ge=0,
        le=1
    )

    document_size: int = Field(..., gt=0)

    metadata_anomaly: int = Field(..., ge=0, le=1)

    replay_indicator: int = Field(..., ge=0, le=1)

    key_age_days: int = Field(..., ge=0)

    time_since_previous: int = Field(..., ge=0)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "success": True,
        "message":
            "Digital Signature Security Threat Detection API",
        "status": "online"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {

        "success": True,

        "status": "healthy",

        "detector_loaded":
            detect_threat is not None,

        "logger_loaded":
            log_security_event is not None,

        "behavioral_features_loaded":
            calculate_behavioral_features is not None,

        "replay_detector_loaded":
            check_replay is not None
    }


# ============================================================
# DIRECT ML DETECTION
# ============================================================

@app.post("/detect")
def detect(event: SecurityEvent):

    if detect_threat is None:

        raise HTTPException(
            status_code=500,
            detail="Threat detector could not be loaded."
        )

    event_data = event.model_dump()

    try:

        result = detect_threat(event_data)

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Threat detection failed: {str(e)}"
        )

    return {
        "success": True,
        "result": result
    }


# ============================================================
# CRYPTOGRAPHIC VERIFICATION
# ============================================================

def verify_digital_signature(
    document_data: bytes,
    signature_data: bytes,
    public_key_data: bytes
):

    try:

        public_key = serialization.load_pem_public_key(
            public_key_data
        )

        public_key.verify(

            signature_data,

            document_data,

            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),

            hashes.SHA256()
        )

        return True, None

    except Exception as e:

        return False, str(e)


# ============================================================
# VERIFY SIGNATURE ONLY
# ============================================================

@app.post("/verify-signature")
async def verify_signature(

    document: UploadFile = File(...),

    signature: UploadFile = File(...),

    public_key: UploadFile = File(...)

):

    document_data = await document.read()

    signature_data = await signature.read()

    public_key_data = await public_key.read()


    if not document_data:

        raise HTTPException(
            status_code=400,
            detail="The document file is empty."
        )


    if not signature_data:

        raise HTTPException(
            status_code=400,
            detail="The signature file is empty."
        )


    if not public_key_data:

        raise HTTPException(
            status_code=400,
            detail="The public key file is empty."
        )


    valid, error = verify_digital_signature(

        document_data,

        signature_data,

        public_key_data
    )


    if valid:

        return {

            "success": True,

            "signature_verification": "VALID",

            "algorithm": "RSA-PSS",

            "hash_algorithm": "SHA-256",

            "document_name":
                document.filename,

            "signature_name":
                signature.filename,

            "public_key_name":
                public_key.filename,

            "document_size":
                len(document_data),

            "signature_size":
                len(signature_data)
        }


    return {

        "success": True,

        "signature_verification": "INVALID",

        "algorithm": "RSA-PSS",

        "hash_algorithm": "SHA-256",

        "document_name":
            document.filename,

        "signature_name":
            signature.filename,

        "public_key_name":
            public_key.filename,

        "document_size":
            len(document_data),

        "signature_size":
            len(signature_data),

        "message":
            "The document does not match "
            "the supplied digital signature."
    }


# ============================================================
# VERIFY + DETECT
# ============================================================

@app.post("/verify-and-detect")
async def verify_and_detect(

    document: UploadFile = File(...),

    signature: UploadFile = File(...),

    public_key: UploadFile = File(...)

):

    # --------------------------------------------------------
    # COMPONENT CHECK
    # --------------------------------------------------------

    if detect_threat is None:

        raise HTTPException(
            status_code=500,
            detail="Threat detector could not be loaded."
        )


    if calculate_behavioral_features is None:

        raise HTTPException(
            status_code=500,
            detail="Behavioral feature engine could not be loaded."
        )


    if check_replay is None:

        raise HTTPException(
            status_code=500,
            detail="Replay detector could not be loaded."
        )


    # --------------------------------------------------------
    # READ FILES
    # --------------------------------------------------------

    document_data = await document.read()

    signature_data = await signature.read()

    public_key_data = await public_key.read()


    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not document_data:

        raise HTTPException(
            status_code=400,
            detail="Document is empty."
        )


    if not signature_data:

        raise HTTPException(
            status_code=400,
            detail="Signature file is empty."
        )


    if not public_key_data:

        raise HTTPException(
            status_code=400,
            detail="Public key file is empty."
        )


    # ========================================================
    # CRYPTOGRAPHIC VERIFICATION
    # ========================================================

    signature_valid, error = (
        verify_digital_signature(

            document_data,

            signature_data,

            public_key_data
        )
    )


    verification_result = (
        1 if signature_valid else 0
    )


    # ========================================================
    # REPLAY DETECTION
    # ========================================================

    try:

        replay_detected = check_replay(
            document_data
        )

        print("=" * 70)
        print("REPLAY DETECTION")
        print("=" * 70)

        print(
            "Replay detected :",
            replay_detected
        )

        print("=" * 70)

    except Exception as e:

        print(
            "Replay detection error:",
            e
        )

        replay_detected = False


    # ========================================================
    # SOURCE
    # ========================================================

    source_id = "local_demo_source"


    # ========================================================
    # BEHAVIORAL FEATURES
    # ========================================================

    try:

        behavioral_features = (
            calculate_behavioral_features(

                verification_result,

                source_id=source_id
            )
        )

        print("=" * 70)
        print("BEHAVIORAL FEATURES CALCULATED")
        print("=" * 70)

        print(
            "Verification frequency :",
            behavioral_features[
                "verification_frequency"
            ]
        )

        print(
            "Source frequency       :",
            behavioral_features[
                "source_frequency"
            ]
        )

        print(
            "Failed verification rate :",
            behavioral_features[
                "failed_verification_rate"
            ]
        )

        print(
            "Time since previous event :",
            behavioral_features[
                "time_since_previous"
            ],
            "seconds"
        )

        print(
            "Current hour :",
            behavioral_features[
                "hour"
            ]
        )

        print("=" * 70)

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                "Behavioral feature calculation failed: "
                f"{str(e)}"
            )
        )


    # ========================================================
    # SECURITY EVENT
    # ========================================================

    event_data = {

        "verification_result":
            verification_result,

        "failed_attempts":
            0 if signature_valid else 1,

        "verification_frequency":
            behavioral_features[
                "verification_frequency"
            ],

        "key_size":
            2048,

        "algorithm":
            "RSA-PSS",

        "hour":
            behavioral_features[
                "hour"
            ],

        "signature_size":
            len(signature_data),

        "certificate_valid":
            1,

        "source_frequency":
            behavioral_features[
                "source_frequency"
            ],

        "failed_verification_rate":
            behavioral_features[
                "failed_verification_rate"
            ],

        "document_size":
            len(document_data),

        "metadata_anomaly":
            0,

        "replay_indicator":
            1 if replay_detected else 0,

        "key_age_days":
            0,

        "time_since_previous":
            behavioral_features[
                "time_since_previous"
            ],

        "source_id":
            source_id
    }


    # ========================================================
    # ML DETECTION
    # ========================================================

    try:

        ml_result = detect_threat(
            event_data
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"ML detection failed: {str(e)}"
        )


    # ========================================================
    # ADD REPLAY INFORMATION
    # ========================================================

    if replay_detected:

        ml_result["replay_detected"] = True

        if "contributing_indicators" in ml_result:

            ml_result[
                "contributing_indicators"
            ].append(
                "Previously processed document detected"
            )

    else:

        ml_result["replay_detected"] = False


    # ========================================================
    # CRYPTOGRAPHIC SECURITY OVERRIDE
    # ========================================================
    #
    # Cryptographic verification has priority when deciding
    # whether a document can be trusted.
    #
    # ML prediction is NOT modified. We preserve the actual
    # ML result and only strengthen the final security
    # assessment when signature verification fails.
    #

    if not signature_valid:

        # The attack category is known from the failed
        # signature verification.
        ml_result["attack_category"] = (
            "DOCUMENT_TAMPERING"
        )

        # Preserve the actual ML probability and prediction.
        # Do not pretend that ML detected something it didn't.
        #
        # However, a cryptographically invalid document must
        # not be presented as a normal security event.

        current_risk = float(
            ml_result.get("risk_score", 0)
        )

        # Minimum risk assigned to a cryptographic failure.
        if current_risk < 40:
            current_risk = 40

        ml_result["risk_score"] = int(
            current_risk
        )

        # Cryptographic failure is at least suspicious.
        ml_result["threat_level"] = "MEDIUM"

        ml_result["assessment"] = (
            "SUSPICIOUS SECURITY EVENT"
        )

        indicators = ml_result.get(
            "contributing_indicators",
            []
        )

        if (
            "Digital signature verification failed"
            not in indicators
        ):

            indicators.insert(
                0,
                "Digital signature verification failed"
            )

        ml_result[
            "contributing_indicators"
        ] = indicators

        ml_result["assessment_explanation"] = [

            "The digital signature verification failed.",

            "The document could not be authenticated "
            "using the supplied signature.",

            "The event has therefore been classified "
            "as suspicious.",

            "ML behavioral analysis is reported "
            "separately and does not override "
            "cryptographic verification."
        ]

        ml_result["recommended_action"] = [

            "Do not trust the document until its "
            "authenticity is verified.",

            "Flag the event for further investigation.",

            "Check the originating source and signature."
        ]


    # ========================================================
    # RECORD DOCUMENT
    # ========================================================
    #
    # Record AFTER detection so that the first request is
    # considered new and a later identical request is a replay.
    #

    try:

        record_document(
            document_data
        )

        print(
            "DOCUMENT FINGERPRINT RECORDED"
        )

    except Exception as e:

        print(
            "Document recording error:",
            e
        )


    # ========================================================
    # SECURITY LOGGER
    # ========================================================

    if log_security_event is not None:

        try:

            log_security_event(

                event_data,

                ml_result
            )

            print(
                "SECURITY EVENT LOGGED SUCCESSFULLY"
            )

        except Exception as e:

            print(
                "Security logging error:",
                e
            )


    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        "success": True,

        "result": {

            "document_name":
                document.filename,

            "signature_name":
                signature.filename,

            "public_key_name":
                public_key.filename,

            "signature_verification":
                (
                    "VALID"
                    if signature_valid
                    else "INVALID"
                ),

            "algorithm":
                "RSA-PSS",

            "hash_algorithm":
                "SHA-256",

            "document_size":
                len(document_data),

            "signature_size":
                len(signature_data),

            "replay_detected":
                replay_detected,

            "ml_detection":
                ml_result
        }
    }