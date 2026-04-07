async function analyzeURL() {
    const url = document.getElementById('urlInput').value.trim();

    if (!url) {
        alert('Please enter a URL');
        return;
    }

    // Show spinner, hide result
    document.getElementById('loadingSpinner').classList.remove('d-none');
    document.getElementById('resultBox').classList.add('d-none');

    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Hide spinner
        document.getElementById('loadingSpinner').classList.add('d-none');

        // Show result
        const resultBox = document.getElementById('resultBox');
        const resultIcon = document.getElementById('resultIcon');
        const resultText = document.getElementById('resultText');
        const resultConfidence = document.getElementById('resultConfidence');
        const resultURL = document.getElementById('resultURL');

        resultBox.classList.remove('d-none', 'safe', 'unsafe');

        if (data.prediction === 'legitimate') {
            resultBox.classList.add('safe');
            resultIcon.innerHTML = '✅';
            resultText.innerHTML = 'This URL appears to be <span class="text-success">Safe</span>';
        } else {
            resultBox.classList.add('unsafe');
            resultIcon.innerHTML = '🚨';
            resultText.innerHTML = 'This URL appears to be <span class="text-danger">Phishing</span>';
        }

        resultConfidence.innerHTML = `Confidence: <strong>${data.confidence}%</strong>`;
        resultURL.innerHTML = `Analyzed: ${data.url}`;

    } catch (error) {
        document.getElementById('loadingSpinner').classList.add('d-none');
        alert('Error analyzing URL. Please try again.');
    }
}

// Allow pressing Enter to analyze
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('urlInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeURL();
    });
});