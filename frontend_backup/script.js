const API_URL = "http://127.0.0.1:8000";


const documentInput = document.getElementById("document");
const signatureInput = document.getElementById("signature");
const publicKeyInput = document.getElementById("publicKey");

const analyzeButton = document.getElementById("analyzeButton");

const loading = document.getElementById("loading");
const resultSection = document.getElementById("resultSection");


analyzeButton.addEventListener("click", analyzeFiles);


async function analyzeFiles() {

    const documentFile = documentInput.files[0];
    const signatureFile = signatureInput.files[0];
    const publicKeyFile = publicKeyInput.files[0];


    // ========================================================
    // CHECK FILES
    // ========================================================

    if (!documentFile) {
        alert("Please select the document file.");
        return;
    }


    if (!signatureFile) {
        alert("Please select the digital signature file.");
        return;
    }


    if (!publicKeyFile) {
        alert("Please select the public key file.");
        return;
    }


    // ========================================================
    // CREATE MULTIPART FORM DATA
    // ========================================================

    const formData = new FormData();

    formData.append("document", documentFile);
    formData.append("signature", signatureFile);
    formData.append("public_key", publicKeyFile);


    // ========================================================
    // SHOW LOADING
    // ========================================================

    loading.classList.remove("hidden");

    resultSection.classList.add("hidden");

    analyzeButton.disabled = true;


    try {

        // ====================================================
        // SEND FILES TO BACKEND
        // ====================================================

        const response = await fetch(
            `${API_URL}/verify-and-detect`,
            {
                method: "POST",
                body: formData
            }
        );


        const data = await response.json();


        // ====================================================
        // HANDLE BACKEND ERROR
        // ====================================================

        if (!response.ok) {

            throw new Error(
                data.detail || "Backend request failed."
            );

        }


        // ====================================================
        // DISPLAY RESULT
        // ====================================================

        displayResult(data.result);


    } catch (error) {

        console.error(error);

        alert(
            "Unable to connect to the backend.\n\n" +
            error.message
        );

    } finally {

        loading.classList.add("hidden");

        analyzeButton.disabled = false;

    }
}


// ============================================================
// DISPLAY SECURITY RESULT
// ============================================================

function displayResult(result) {

    const ml = result.ml_detection;


    resultSection.classList.remove("hidden");


    // ========================================================
    // BASIC RESULTS
    // ========================================================

    document.getElementById(
        "signatureVerification"
    ).textContent =
        result.signature_verification;


    document.getElementById(
        "mlPrediction"
    ).textContent =
        ml.ml_prediction;


    document.getElementById(
        "threatProbability"
    ).textContent =
        `${ml.ml_threat_probability}%`;


    document.getElementById(
        "riskScore"
    ).textContent =
        `${ml.risk_score} / 100`;


    document.getElementById(
        "threatLevel"
    ).textContent =
        ml.threat_level;


    document.getElementById(
        "attackCategory"
    ).textContent =
        ml.attack_category;


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

    document.getElementById(
        "assessment"
    ).textContent =
        ml.assessment;


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
}


// ============================================================
// POPULATE LIST
// ============================================================

function populateList(elementId, items) {

    const list = document.getElementById(elementId);

    list.innerHTML = "";


    if (!items || items.length === 0) {

        const li = document.createElement("li");

        li.textContent = "None";

        list.appendChild(li);

        return;
    }


    items.forEach(item => {

        const li = document.createElement("li");

        li.textContent = item;

        list.appendChild(li);

    });
}