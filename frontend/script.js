"use strict";


// ============================================================
// CONFIGURATION
// ============================================================

const API_URL = "http://127.0.0.1:8000";


// ============================================================
// PAGE LOAD TEST
// ============================================================

console.log("======================================");
console.log("SIH26141 FRONTEND LOADED");
console.log("API:", API_URL);
console.log("======================================");


// ============================================================
// ELEMENTS
// ============================================================

const documentInput =
    document.getElementById("document");

const signatureInput =
    document.getElementById("signature");

const publicKeyInput =
    document.getElementById("publicKey");

const analyzeButton =
    document.getElementById("analyzeButton");

const loading =
    document.getElementById("loading");

const resultSection =
    document.getElementById("resultSection");

const errorMessage =
    document.getElementById("errorMessage");


// ============================================================
// VERIFY ELEMENTS
// ============================================================

console.log(
    "Document input:",
    documentInput
);

console.log(
    "Signature input:",
    signatureInput
);

console.log(
    "Public key input:",
    publicKeyInput
);

console.log(
    "Analyze button:",
    analyzeButton
);

console.log(
    "Result section:",
    resultSection
);


// ============================================================
// BUTTON
// ============================================================

if (!analyzeButton) {

    alert(
        "ERROR: Verify & Analyze button was not found."
    );

} else {

    analyzeButton.addEventListener(
        "click",
        analyzeFiles
    );

}


// ============================================================
// ANALYZE FILES
// ============================================================

async function analyzeFiles() {

    console.log(
        "VERIFY & ANALYZE BUTTON CLICKED"
    );


    // --------------------------------------------------------
    // CLEAR OLD ERROR
    // --------------------------------------------------------

    hideError();


    // --------------------------------------------------------
    // GET FILES
    // --------------------------------------------------------

    const documentFile =
        documentInput.files[0];

    const signatureFile =
        signatureInput.files[0];

    const publicKeyFile =
        publicKeyInput.files[0];


    console.log(
        "Document:",
        documentFile
    );

    console.log(
        "Signature:",
        signatureFile
    );

    console.log(
        "Public key:",
        publicKeyFile
    );


    // --------------------------------------------------------
    // VALIDATION
    // --------------------------------------------------------

    if (!documentFile) {

        showError(
            "Please select the document file."
        );

        return;
    }


    if (!signatureFile) {

        showError(
            "Please select the digital signature file."
        );

        return;
    }


    if (!publicKeyFile) {

        showError(
            "Please select the public key file."
        );

        return;
    }


    // --------------------------------------------------------
    // FORM DATA
    // --------------------------------------------------------

    const formData =
        new FormData();


    formData.append(
        "document",
        documentFile
    );

    formData.append(
        "signature",
        signatureFile
    );

    formData.append(
        "public_key",
        publicKeyFile
    );


    // --------------------------------------------------------
    // UI
    // --------------------------------------------------------

    analyzeButton.disabled = true;

    loading.classList.remove(
        "hidden"
    );

    resultSection.classList.add(
        "hidden"
    );


    try {

        console.log(
            "Sending request..."
        );


        // ====================================================
        // API CALL
        // ====================================================

        const response =
            await fetch(
                `${API_URL}/verify-and-detect`,
                {
                    method: "POST",
                    body: formData
                }
            );


        console.log(
            "HTTP status:",
            response.status
        );


        // ====================================================
        // RESPONSE
        // ====================================================

        const responseText =
            await response.text();


        console.log(
            "Raw backend response:",
            responseText
        );


        let data;


        try {

            data =
                JSON.parse(
                    responseText
                );

        } catch (jsonError) {

            throw new Error(
                "Backend returned invalid JSON."
            );
        }


        console.log(
            "Parsed backend response:",
            data
        );


        // ====================================================
        // HTTP ERROR
        // ====================================================

        if (!response.ok) {

            let message =
                "Backend request failed.";

            if (data.detail) {

                if (
                    typeof data.detail === "string"
                ) {

                    message =
                        data.detail;

                } else {

                    message =
                        JSON.stringify(
                            data.detail
                        );
                }
            }


            throw new Error(
                message
            );
        }


        // ====================================================
        // SUCCESS CHECK
        // ====================================================

        if (
            data.success !== true
        ) {

            throw new Error(
                "Backend returned success=false."
            );
        }


        if (!data.result) {

            throw new Error(
                "Backend response does not contain result."
            );
        }


        console.log(
            "Displaying result..."
        );


        // ====================================================
        // DISPLAY
        // ====================================================

        displayResult(
            data.result
        );


    } catch (error) {

        console.error(
            "======================================"
        );

        console.error(
            "FRONTEND ERROR"
        );

        console.error(
            error
        );

        console.error(
            "======================================"
        );


        showError(
            error.message
        );


    } finally {

        analyzeButton.disabled =
            false;

        loading.classList.add(
            "hidden"
        );

    }
}


// ============================================================
// DISPLAY RESULT
// ============================================================

function displayResult(result) {

    console.log(
        "RESULT OBJECT:",
        result
    );


    // --------------------------------------------------------
    // ML OBJECT
    // --------------------------------------------------------

    const ml =
        result.ml_detection;


    if (!ml) {

        throw new Error(
            "ml_detection is missing from backend response."
        );
    }


    // ========================================================
    // CRYPTOGRAPHIC VERIFICATION
    // ========================================================

    setText(
        "signatureVerification",
        result.signature_verification
    );


    setText(
        "algorithm",
        result.algorithm
    );


    setText(
        "hashAlgorithm",
        result.hash_algorithm
    );


    const authenticationIcon =
        document.getElementById(
            "authenticationIcon"
        );


    if (
        result.signature_verification === "VALID"
    ) {

        authenticationIcon.textContent =
            "✓";

    } else {

        authenticationIcon.textContent =
            "✕";
    }


    // ========================================================
    // ML
    // ========================================================

    setText(
        "mlPrediction",
        ml.ml_prediction
    );


    setText(
        "threatProbability",
        formatProbability(
            ml.ml_threat_probability
        )
    );


    setText(
        "riskScore",
        ml.risk_score
    );


    setText(
        "threatLevel",
        ml.threat_level
    );


    setText(
        "attackCategory",
        ml.attack_category
    );


    // ========================================================
    // RISK
    // ========================================================

    const risk =
        Number(
            ml.risk_score
        );


    const safeRisk =
        Number.isFinite(risk)
            ? Math.max(
                0,
                Math.min(
                    100,
                    risk
                )
            )
            : 0;


    setText(
        "riskText",
        `${safeRisk} / 100`
    );


    const riskFill =
        document.getElementById(
            "riskFill"
        );


    if (riskFill) {

        riskFill.style.width =
            `${safeRisk}%`;
    }


    // ========================================================
    // REPLAY
    // ========================================================

    const replayElement =
        document.getElementById(
            "replayStatus"
        );


    if (replayElement) {

        if (
            result.replay_detected === true
        ) {

            replayElement.textContent =
                "REPLAY DETECTED";

        } else {

            replayElement.textContent =
                "NEW DOCUMENT";
        }
    }


    // ========================================================
    // INDICATORS
    // ========================================================

    populateList(
        "indicators",
        ml.contributing_indicators
    );


    // ========================================================
    // ASSESSMENT
    // ========================================================

    setText(
        "assessment",
        ml.assessment
    );


    // ========================================================
    // EXPLANATION
    // ========================================================

    populateList(
        "explanation",
        ml.assessment_explanation
    );


    // ========================================================
    // RECOMMENDATIONS
    // ========================================================

    populateList(
        "recommendations",
        ml.recommended_action
    );


    // ========================================================
    // SHOW RESULT
    // ========================================================

    resultSection.classList.remove(
        "hidden"
    );


    console.log(
        "RESULT DISPLAYED SUCCESSFULLY"
    );


    // ========================================================
    // SCROLL
    // ========================================================

    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// ============================================================
// SET TEXT
// ============================================================

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {

        console.warn(
            `Element not found: ${elementId}`
        );

        return;
    }


    if (
        value === null ||
        value === undefined
    ) {

        element.textContent =
            "-";

    } else {

        element.textContent =
            String(value);
    }
}


// ============================================================
// PROBABILITY
// ============================================================

function formatProbability(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "-";
    }


    const number =
        Number(value);


    if (
        !Number.isFinite(number)
    ) {

        return "-";
    }


    return `${number}%`;
}


// ============================================================
// LIST
// ============================================================

function populateList(
    elementId,
    items
) {

    const list =
        document.getElementById(
            elementId
        );


    if (!list) {

        console.warn(
            `List not found: ${elementId}`
        );

        return;
    }


    list.innerHTML = "";


    if (
        !Array.isArray(items) ||
        items.length === 0
    ) {

        const item =
            document.createElement(
                "li"
            );

        item.textContent =
            "None detected.";

        list.appendChild(
            item
        );

        return;
    }


    items.forEach(
        text => {

            const item =
                document.createElement(
                    "li"
                );

            item.textContent =
                text;

            list.appendChild(
                item
            );

        }
    );
}


// ============================================================
// ERROR DISPLAY
// ============================================================

function showError(
    message
) {

    if (!errorMessage) {

        alert(
            message
        );

        return;
    }


    errorMessage.textContent =
        `ERROR: ${message}`;


    errorMessage.classList.remove(
        "hidden"
    );


    errorMessage.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


// ============================================================
// HIDE ERROR
// ============================================================

function hideError() {

    if (!errorMessage) {
        return;
    }


    errorMessage.textContent =
        "";


    errorMessage.classList.add(
        "hidden"
    );
}