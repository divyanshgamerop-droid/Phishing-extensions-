document.getElementById("scanButton").addEventListener("click", async () => {

    const result = document.getElementById("result");

    result.innerText = "Scanning...";

    try {

        const tabs = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        const url = tabs[0].url;

        let riskScore = 0;
        let reasons = [];

        // HTTPS check
        if (!url.startsWith("https://")) {
            riskScore += 20;
            reasons.push("Website is not using HTTPS");
        }

        // URL length
        if (url.length > 100) {
            riskScore += 15;
            reasons.push("URL is unusually long");
        }

        // Suspicious keywords
        const suspiciousWords = [
            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "update",
            "password",
            "bank",
            "payment"
        ];

        for (const word of suspiciousWords) {

            if (url.toLowerCase().includes(word)) {
                riskScore += 10;
                reasons.push(
                    `Suspicious keyword detected: ${word}`
                );
                break;
            }
        }

        // @ symbol
        if (url.includes("@")) {
            riskScore += 25;
            reasons.push("URL contains @ symbol");
        }

        // IP address detection
        const ipPattern =
            /https?:\/\/(\d{1,3}\.){3}\d{1,3}/;

        if (ipPattern.test(url)) {
            riskScore += 30;
            reasons.push("URL uses an IP address instead of a normal domain");
        }

        // Final classification
        let riskLevel;

        if (riskScore >= 60) {
            riskLevel = "DANGEROUS";
        } else if (riskScore >= 30) {
            riskLevel = "SUSPICIOUS";
        } else {
            riskLevel = "SAFE";
        }

        if (reasons.length === 0) {
            reasons.push("No basic phishing indicators detected");
        }

        result.innerHTML = `
            <h3>${riskLevel}</h3>

            <p>
                <b>Risk Score:</b> ${riskScore}/100
            </p>

            <p>
                <b>URL:</b><br>
                ${url}
            </p>

            <p>
                <b>Reasons:</b>
            </p>

            <ul>
                ${reasons.map(reason => `<li>${reason}</li>`).join("")}
            </ul>
        `;

    } catch (error) {

        result.innerText =
            "Unable to scan this page: " + error.message;

    }

});